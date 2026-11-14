/* Copyright (C) The libssh2 project and its contributors.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/* Integration tests for the channel receive-window accounting in
 * ssh2_packet_add() / ssh2_channel_read().
 *
 * The receive window and the length of incoming data both originate from
 * the peer's protocol packets, so malformed packets must not be able to
 * desynchronize the accounting. These tests feed crafted packets directly
 * into the packet dispatcher (no network, no container) and verify:
 *
 *  - SSH_MSG_CHANNEL_WINDOW_ADJUST values near UINT32_MAX are rejected
 *    without wrapping the window, and later valid adjusts still apply.
 *  - SSH_MSG_CHANNEL_DATA that exceeds the current window or the
 *    negotiated packet size is truncated to the permitted boundary; the
 *    accepted byte count and the remaining window never wrap around and
 *    subsequent legal packets are still read correctly.
 *  - Ignored SSH_MSG_CHANNEL_EXTENDED_DATA is refunded exactly once, also
 *    when the window adjust would block (EAGAIN) and is retried, and
 *    normal and extended data keep identical books after such a retry.
 *  - Packets arriving for a closed channel are dropped: they neither
 *    resurrect the old channel nor get delivered to a new one.
 */

#include "libssh2_priv.h"
#include "packet.h"
#include "channel.h"
#include "misc.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * In-memory transport: the session never touches a real socket. Outgoing
 * data (window adjusts, channel close) is captured in sent_buf so the
 * tests can inspect the plaintext SSH packets; incoming data is always
 * "would block" because every packet is fed directly via ssh2_packet_add().
 */

static unsigned char sent_buf[16384];
static size_t sent_len;
static int send_would_block;

static LIBSSH2_SEND_FUNC(test_send)
{
    (void)socket;
    (void)flags;
    (void)abstract;

    if(send_would_block)
        return -EAGAIN;

    if(length > sizeof(sent_buf) - sent_len) {
        fprintf(stderr, "sent_buf overflow\n");
        exit(1);
    }
    memcpy(sent_buf + sent_len, buffer, length);
    sent_len += length;
    return (ssize_t)length;
}

static LIBSSH2_RECV_FUNC(test_recv)
{
    (void)socket;
    (void)buffer;
    (void)length;
    (void)flags;
    (void)abstract;

    return -EAGAIN;
}

static void wire_reset(void)
{
    sent_len = 0;
}

/* Parse the captured plaintext SSH packets and count
   SSH_MSG_CHANNEL_WINDOW_ADJUST packets, summing their adjustments.
   Returns the packet count, or -1 if the stream is unparsable. */
static int wire_window_adjusts(uint32_t *total_adjustment)
{
    size_t pos = 0;
    int count = 0;

    *total_adjustment = 0;

    while(pos < sent_len) {
        uint32_t plen;
        unsigned char padlen;

        if(sent_len - pos < 5)
            return -1;
        plen = ssh2_ntohu32(sent_buf + pos);
        padlen = sent_buf[pos + 4];
        if(plen < (uint32_t)padlen + 2 || (size_t)plen > sent_len - pos - 4)
            return -1;
        if(sent_buf[pos + 5] == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
            if(plen - padlen - 1 != 9)
                return -1;
            count++;
            *total_adjustment += ssh2_ntohu32(sent_buf + pos + 10);
        }
        pos += 4 + plen;
    }

    return count;
}

static LIBSSH2_SESSION *test_session(void)
{
    LIBSSH2_SESSION *session = libssh2_session_init();
    if(!session)
        return NULL;

    session->send_cb = test_send;
    session->recv_cb = test_recv;
    session->socket_state = SSH2_SOCKET_CONNECTED;
    libssh2_session_set_blocking(session, 0);

    wire_reset();
    send_would_block = 0;

    return session;
}

static LIBSSH2_CHANNEL *test_channel(LIBSSH2_SESSION *session,
                                     uint32_t local_id, uint32_t remote_id,
                                     uint32_t window, uint32_t packet_size)
{
    LIBSSH2_CHANNEL *channel = SSH2_CALLOC(session, sizeof(*channel));
    if(!channel)
        return NULL;

    channel->session = session;
    channel->local.id = local_id;
    channel->local.window_size = window;
    channel->local.window_size_initial = window;
    channel->remote.id = remote_id;
    channel->remote.window_size = window;
    channel->remote.window_size_initial = window;
    channel->remote.packet_size = packet_size;

    ssh2_list_add(&session->channels, &channel->node);

    return channel;
}

/* Build an SSH_MSG_CHANNEL_DATA packet. inner_len is the (possibly
   dishonest) string length field inside the packet. */
static size_t make_channel_data(unsigned char *buf, uint32_t channel_id,
                                const void *payload, uint32_t payload_len,
                                uint32_t inner_len)
{
    unsigned char *s = buf;

    *s++ = SSH_MSG_CHANNEL_DATA;
    ssh2_store_u32(&s, channel_id);
    ssh2_store_u32(&s, inner_len);
    memcpy(s, payload, payload_len);

    return 9 + payload_len;
}

static size_t make_extended_data(unsigned char *buf, uint32_t channel_id,
                                 uint32_t type_code,
                                 const void *payload, uint32_t payload_len)
{
    unsigned char *s = buf;

    *s++ = SSH_MSG_CHANNEL_EXTENDED_DATA;
    ssh2_store_u32(&s, channel_id);
    ssh2_store_u32(&s, type_code);
    ssh2_store_u32(&s, payload_len);
    memcpy(s, payload, payload_len);

    return 13 + payload_len;
}

static size_t make_window_adjust(unsigned char *buf, uint32_t channel_id,
                                 uint32_t bytestoadd)
{
    unsigned char *s = buf;

    *s++ = SSH_MSG_CHANNEL_WINDOW_ADJUST;
    ssh2_store_u32(&s, channel_id);
    ssh2_store_u32(&s, bytestoadd);

    return 9;
}

/* Hand a received packet to the dispatcher. The packet is copied into
   session-allocated memory which ssh2_packet_add() takes ownership of
   (unless it returns LIBSSH2_ERROR_EAGAIN). */
static int feed(LIBSSH2_SESSION *session, const unsigned char *pkt,
                size_t pkt_len)
{
    unsigned char *copy = SSH2_ALLOC(session, pkt_len);
    if(!copy)
        return LIBSSH2_ERROR_ALLOC;
    memcpy(copy, pkt, pkt_len);
    return ssh2_packet_add(session, copy, pkt_len, 0, 0);
}

static int packets_queued(LIBSSH2_SESSION *session)
{
    return ssh2_list_first(&session->packets) != NULL;
}

/* Feed the peer's SSH_MSG_CHANNEL_CLOSE acknowledgment and free the
   channel, completing the close handshake a real server would do. */
static int test_channel_free(LIBSSH2_CHANNEL *channel)
{
    LIBSSH2_SESSION *session = channel->session;
    unsigned char pkt[5];
    unsigned char *s = pkt;
    int rc;

    *s++ = SSH_MSG_CHANNEL_CLOSE;
    ssh2_store_u32(&s, channel->local.id);

    rc = feed(session, pkt, sizeof(pkt));
    if(rc)
        return rc;

    return ssh2_channel_free(channel);
}

/*
 * SSH_MSG_CHANNEL_WINDOW_ADJUST with values near the 32-bit limit must be
 * rejected without wrapping the send window; valid adjusts must still
 * apply afterwards.
 */
static int test_window_adjust_bounds(void)
{
    static const uint32_t local_id = 0;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    unsigned char pkt[9];
    size_t pkt_len;
    int rc;
    int err = 0;

    session = test_session();
    channel = session ? test_channel(session, local_id, 17,
                                     0xFFFFFF00, 32768) : NULL;
    if(!channel) {
        fprintf(stderr, "window_adjust_bounds: setup failed\n");
        return 1;
    }

    /* adjust that would wrap the window past UINT32_MAX */
    pkt_len = make_window_adjust(pkt, local_id, 0x200);
    rc = feed(session, pkt, pkt_len);
    if(rc != LIBSSH2_ERROR_PROTO) {
        fprintf(stderr, "window_adjust_bounds: overflow rc=%d (want %d)\n",
                rc, LIBSSH2_ERROR_PROTO);
        err++;
    }
    if(channel->local.window_size != 0xFFFFFF00) {
        fprintf(stderr, "window_adjust_bounds: window wrapped to %u\n",
                channel->local.window_size);
        err++;
    }

    /* adjust that lands exactly on UINT32_MAX: allowed, no wrap */
    pkt_len = make_window_adjust(pkt, local_id, 0xFF);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0 || channel->local.window_size != UINT32_MAX) {
        fprintf(stderr, "window_adjust_bounds: boundary adjust rc=%d "
                "window=%u (want 0/%u)\n",
                rc, channel->local.window_size, UINT32_MAX);
        err++;
    }

    /* one more byte must now be rejected, window stays pinned */
    pkt_len = make_window_adjust(pkt, local_id, 1);
    rc = feed(session, pkt, pkt_len);
    if(rc != LIBSSH2_ERROR_PROTO ||
       channel->local.window_size != UINT32_MAX) {
        fprintf(stderr, "window_adjust_bounds: pinned adjust rc=%d "
                "window=%u (want %d/%u)\n",
                rc, channel->local.window_size,
                LIBSSH2_ERROR_PROTO, UINT32_MAX);
        err++;
    }

    /* a zero adjust is always legal and changes nothing */
    pkt_len = make_window_adjust(pkt, local_id, 0);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0 || channel->local.window_size != UINT32_MAX) {
        fprintf(stderr, "window_adjust_bounds: zero adjust rc=%d "
                "window=%u\n", rc, channel->local.window_size);
        err++;
    }

    /* adjust for an unknown channel is ignored without error */
    pkt_len = make_window_adjust(pkt, 99, 100);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0 || channel->local.window_size != UINT32_MAX) {
        fprintf(stderr, "window_adjust_bounds: unknown channel rc=%d\n", rc);
        err++;
    }

    /* truncated adjust packet (no room for the amount) is ignored */
    pkt_len = make_window_adjust(pkt, local_id, 100);
    rc = feed(session, pkt, 5);
    if(rc != 0 || channel->local.window_size != UINT32_MAX) {
        fprintf(stderr, "window_adjust_bounds: truncated packet rc=%d\n", rc);
        err++;
    }

    if(test_channel_free(channel))
        err++;
    libssh2_session_free(session);

    return err > 0;
}

/*
 * SSH_MSG_CHANNEL_DATA carrying more than the current receive window is
 * truncated to the window boundary; once the window is full further data
 * is dropped. Nothing wraps, and after draining, legal packets flow again.
 */
static int test_channel_data_exceeds_window(void)
{
    static const uint32_t local_id = 0;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    unsigned char pkt[9 + 100];
    unsigned char payload[100];
    unsigned char buf[100];
    size_t pkt_len;
    uint32_t adjust_total = 0;
    ssize_t n;
    int adjusts;
    int rc;
    int err = 0;
    int i;

    for(i = 0; i < 100; i++)
        payload[i] = (unsigned char)i;

    session = test_session();
    channel = session ? test_channel(session, local_id, 17, 64, 128) : NULL;
    if(!channel) {
        fprintf(stderr, "data_exceeds_window: setup failed\n");
        return 1;
    }

    /* 100 bytes offered, window only allows 64 */
    pkt_len = make_channel_data(pkt, local_id, payload, 100, 100);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0) {
        fprintf(stderr, "data_exceeds_window: feed rc=%d\n", rc);
        err++;
    }
    if(channel->read_avail != 64) {
        fprintf(stderr, "data_exceeds_window: read_avail=%lu (want 64)\n",
                (unsigned long)channel->read_avail);
        err++;
    }
    if(libssh2_session_last_errno(session) !=
       LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED) {
        fprintf(stderr, "data_exceeds_window: last errno=%d (want %d)\n",
                libssh2_session_last_errno(session),
                LIBSSH2_ERROR_CHANNEL_WINDOW_EXCEEDED);
        err++;
    }
    if(ssh2_channel_packet_data_len(channel, 0) != 64) {
        fprintf(stderr, "data_exceeds_window: queued=%lu (want 64)\n",
                (unsigned long)ssh2_channel_packet_data_len(channel, 0));
        err++;
    }

    /* window now full: another data packet is dropped entirely */
    pkt_len = make_channel_data(pkt, local_id, payload, 10, 10);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0 || channel->read_avail != 64 ||
       ssh2_channel_packet_data_len(channel, 0) != 64) {
        fprintf(stderr, "data_exceeds_window: full-window packet leaked: "
                "rc=%d read_avail=%lu\n",
                rc, (unsigned long)channel->read_avail);
        err++;
    }

    /* drain the window; only the truncated 64 bytes may come out */
    wire_reset();
    n = ssh2_channel_read(channel, 0, (char *)buf, 64);
    if(n != 64 || memcmp(buf, payload, 64)) {
        fprintf(stderr, "data_exceeds_window: read n=%ld (want 64)\n",
                (long)n);
        err++;
    }
    if(channel->read_avail != 0) {
        fprintf(stderr, "data_exceeds_window: read_avail=%lu after read\n",
                (unsigned long)channel->read_avail);
        err++;
    }
    /* the read refills the window to at least LIBSSH2_CHANNEL_MINADJUST */
    if(channel->remote.window_size != LIBSSH2_CHANNEL_MINADJUST) {
        fprintf(stderr, "data_exceeds_window: window=%u after read "
                "(want %d)\n",
                channel->remote.window_size, LIBSSH2_CHANNEL_MINADJUST);
        err++;
    }
    adjusts = wire_window_adjusts(&adjust_total);
    if(adjusts != 1 || adjust_total != LIBSSH2_CHANNEL_MINADJUST) {
        fprintf(stderr, "data_exceeds_window: wire adjusts=%d total=%u "
                "(want 1/%d)\n",
                adjusts, adjust_total, LIBSSH2_CHANNEL_MINADJUST);
        err++;
    }

    /* a subsequent legal packet is still received correctly */
    pkt_len = make_channel_data(pkt, local_id, payload, 8, 8);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0 || channel->read_avail != 8) {
        fprintf(stderr, "data_exceeds_window: legal packet rc=%d "
                "read_avail=%lu (want 8)\n",
                rc, (unsigned long)channel->read_avail);
        err++;
    }
    n = ssh2_channel_read(channel, 0, (char *)buf, 8);
    if(n != 8 || memcmp(buf, payload, 8)) {
        fprintf(stderr, "data_exceeds_window: legal read n=%ld (want 8)\n",
                (long)n);
        err++;
    }

    if(test_channel_free(channel))
        err++;
    libssh2_session_free(session);

    return err > 0;
}

/*
 * SSH_MSG_CHANNEL_DATA carrying more than the negotiated packet size is
 * truncated to the packet size boundary.
 */
static int test_channel_data_exceeds_packet_size(void)
{
    static const uint32_t local_id = 0;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    unsigned char pkt[9 + 100];
    unsigned char payload[100];
    unsigned char buf[16];
    size_t pkt_len;
    ssize_t n;
    int rc;
    int err = 0;
    int i;

    for(i = 0; i < 100; i++)
        payload[i] = (unsigned char)(0xA0 + i);

    session = test_session();
    channel = session ? test_channel(session, local_id, 17, 4096, 16) : NULL;
    if(!channel) {
        fprintf(stderr, "data_exceeds_packet_size: setup failed\n");
        return 1;
    }

    pkt_len = make_channel_data(pkt, local_id, payload, 100, 100);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0) {
        fprintf(stderr, "data_exceeds_packet_size: feed rc=%d\n", rc);
        err++;
    }
    if(channel->read_avail != 16) {
        fprintf(stderr, "data_exceeds_packet_size: read_avail=%lu "
                "(want 16)\n", (unsigned long)channel->read_avail);
        err++;
    }
    if(libssh2_session_last_errno(session) !=
       LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED) {
        fprintf(stderr, "data_exceeds_packet_size: last errno=%d "
                "(want %d)\n",
                libssh2_session_last_errno(session),
                LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED);
        err++;
    }

    n = ssh2_channel_read(channel, 0, (char *)buf, sizeof(buf));
    if(n != 16 || memcmp(buf, payload, 16)) {
        fprintf(stderr, "data_exceeds_packet_size: read n=%ld (want 16)\n",
                (long)n);
        err++;
    }
    if(channel->read_avail != 0 ||
       channel->remote.window_size != 4096 - 16) {
        fprintf(stderr, "data_exceeds_packet_size: read_avail=%lu "
                "window=%u after read\n",
                (unsigned long)channel->read_avail,
                channel->remote.window_size);
        err++;
    }

    if(test_channel_free(channel))
        err++;
    libssh2_session_free(session);

    return err > 0;
}

/*
 * The string length inside SSH_MSG_CHANNEL_DATA lies (claims nearly 4GB
 * while only 4 bytes are on the wire): the transport framing, not the
 * inner length, must govern the accounting.
 */
static int test_channel_data_inner_length_lies(void)
{
    static const uint32_t local_id = 0;
    static const unsigned char payload[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    unsigned char pkt[9 + 4];
    unsigned char buf[4];
    size_t pkt_len;
    ssize_t n;
    int rc;
    int err = 0;

    session = test_session();
    channel = session ? test_channel(session, local_id, 17, 128, 256) : NULL;
    if(!channel) {
        fprintf(stderr, "inner_length_lies: setup failed\n");
        return 1;
    }

    pkt_len = make_channel_data(pkt, local_id, payload, 4, 0xFFFFFFF0);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0 || channel->read_avail != 4) {
        fprintf(stderr, "inner_length_lies: rc=%d read_avail=%lu (want 4)\n",
                rc, (unsigned long)channel->read_avail);
        err++;
    }

    n = ssh2_channel_read(channel, 0, (char *)buf, sizeof(buf));
    if(n != 4 || memcmp(buf, payload, 4)) {
        fprintf(stderr, "inner_length_lies: read n=%ld (want 4)\n", (long)n);
        err++;
    }

    if(test_channel_free(channel))
        err++;
    libssh2_session_free(session);

    return err > 0;
}

/*
 * Ignored extended data refunds the window exactly once and leaves no
 * queued bytes behind; normal data afterwards is received correctly.
 */
static int test_extended_data_ignored(void)
{
    static const uint32_t local_id = 0;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    unsigned char pkt[13 + 40];
    unsigned char payload[40];
    unsigned char buf[10];
    size_t pkt_len;
    uint32_t adjust_total = 0;
    ssize_t n;
    int adjusts;
    int rc;
    int err = 0;
    int i;

    for(i = 0; i < 40; i++)
        payload[i] = (unsigned char)(0x40 + i);

    session = test_session();
    channel = session ? test_channel(session, local_id, 17, 128, 256) : NULL;
    if(!channel) {
        fprintf(stderr, "extended_data_ignored: setup failed\n");
        return 1;
    }
    channel->remote.extended_data_ignore_mode =
        LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE;

    pkt_len = make_extended_data(pkt, local_id, 1, payload, 40);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0) {
        fprintf(stderr, "extended_data_ignored: feed rc=%d\n", rc);
        err++;
    }
    if(channel->read_avail != 0 || packets_queued(session)) {
        fprintf(stderr, "extended_data_ignored: ignored packet left "
                "read_avail=%lu queued=%d\n",
                (unsigned long)channel->read_avail, packets_queued(session));
        err++;
    }
    if(channel->remote.window_size != 128) {
        fprintf(stderr, "extended_data_ignored: window=%u (want 128)\n",
                channel->remote.window_size);
        err++;
    }
    adjusts = wire_window_adjusts(&adjust_total);
    if(adjusts != 1 || adjust_total != 40) {
        fprintf(stderr, "extended_data_ignored: wire adjusts=%d total=%u "
                "(want 1/40)\n", adjusts, adjust_total);
        err++;
    }

    /* normal data after the ignored extended data still arrives */
    pkt_len = make_channel_data(pkt, local_id, payload, 10, 10);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0 || channel->read_avail != 10) {
        fprintf(stderr, "extended_data_ignored: follow-up rc=%d "
                "read_avail=%lu (want 10)\n",
                rc, (unsigned long)channel->read_avail);
        err++;
    }
    n = ssh2_channel_read(channel, 0, (char *)buf, sizeof(buf));
    if(n != 10 || memcmp(buf, payload, 10)) {
        fprintf(stderr, "extended_data_ignored: follow-up read n=%ld\n",
                (long)n);
        err++;
    }

    if(test_channel_free(channel))
        err++;
    libssh2_session_free(session);

    return err > 0;
}

/*
 * Same as above, but the window adjust would block (EAGAIN) on the first
 * attempt. The retry must complete the refund exactly once, ending with
 * the same accounting as the non-blocking case.
 */
static int test_extended_data_ignored_eagain_retry(void)
{
    static const uint32_t local_id = 0;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    unsigned char pkt[13 + 40];
    unsigned char payload[40];
    unsigned char *copy;
    size_t pkt_len;
    uint32_t adjust_total = 0;
    int adjusts;
    int rc;
    int err = 0;
    int i;

    for(i = 0; i < 40; i++)
        payload[i] = (unsigned char)(0x60 + i);

    session = test_session();
    channel = session ? test_channel(session, local_id, 17, 128, 256) : NULL;
    if(!channel) {
        fprintf(stderr, "extended_data_eagain: setup failed\n");
        return 1;
    }
    channel->remote.extended_data_ignore_mode =
        LIBSSH2_CHANNEL_EXTENDED_DATA_IGNORE;

    pkt_len = make_extended_data(pkt, local_id, 1, payload, 40);

    copy = SSH2_ALLOC(session, pkt_len);
    if(!copy) {
        libssh2_session_free(session);
        return 1;
    }
    memcpy(copy, pkt, pkt_len);

    /* the window adjust cannot go out: the packet stays pending */
    send_would_block = 1;
    rc = ssh2_packet_add(session, copy, pkt_len, 0, 0);
    if(rc != LIBSSH2_ERROR_EAGAIN) {
        fprintf(stderr, "extended_data_eagain: first rc=%d (want %d)\n",
                rc, LIBSSH2_ERROR_EAGAIN);
        SSH2_FREE(session, copy);
        err++;
        goto done;
    }
    /* the window was debited but not yet refunded */
    if(channel->remote.window_size != 128 - 40) {
        fprintf(stderr, "extended_data_eagain: window mid-retry=%u "
                "(want %u)\n", channel->remote.window_size, 128U - 40);
        err++;
    }
    if(channel->read_avail != 0 || packets_queued(session)) {
        fprintf(stderr, "extended_data_eagain: bytes queued mid-retry\n");
        err++;
    }
    adjusts = wire_window_adjusts(&adjust_total);
    if(adjusts != 0) {
        fprintf(stderr, "extended_data_eagain: adjust sent despite "
                "EAGAIN\n");
        err++;
    }

    /* retry with the same packet, as the transport layer would */
    send_would_block = 0;
    rc = ssh2_packet_add(session, copy, pkt_len, 0, 0);
    if(rc != 0) {
        fprintf(stderr, "extended_data_eagain: retry rc=%d\n", rc);
        err++;
    }
    /* refunded exactly once: identical to the non-blocking case */
    if(channel->remote.window_size != 128 || channel->read_avail != 0) {
        fprintf(stderr, "extended_data_eagain: window=%u read_avail=%lu "
                "after retry (want 128/0)\n",
                channel->remote.window_size,
                (unsigned long)channel->read_avail);
        err++;
    }
    adjusts = wire_window_adjusts(&adjust_total);
    if(adjusts != 1 || adjust_total != 40) {
        fprintf(stderr, "extended_data_eagain: wire adjusts=%d total=%u "
                "(want 1/40)\n", adjusts, adjust_total);
        err++;
    }

    /* the channel keeps accepting packets afterwards */
    pkt_len = make_channel_data(pkt, local_id, payload, 10, 10);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0 || channel->read_avail != 10) {
        fprintf(stderr, "extended_data_eagain: follow-up rc=%d "
                "read_avail=%lu (want 10)\n",
                rc, (unsigned long)channel->read_avail);
        err++;
    }

done:
    if(test_channel_free(channel))
        err++;
    libssh2_session_free(session);

    return err > 0;
}

/*
 * A channel read that triggers a window adjust may would-block in the
 * middle. After the retry, normal data (stream 0) and extended data
 * (stream 1) must show identical window accounting.
 */
static int test_read_retry_accounting(void)
{
    static const uint32_t local_id = 0;
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    unsigned char pkt[13 + 64];
    unsigned char payload[64];
    unsigned char buf[64];
    size_t pkt_len;
    uint32_t adjust_total = 0;
    uint32_t window_after[2] = { 0, 0 };
    size_t avail_after[2] = { 0, 0 };
    ssize_t n;
    int adjusts;
    int rc;
    int err = 0;
    int stream;
    int i;

    for(i = 0; i < 64; i++)
        payload[i] = (unsigned char)(0x80 + i);

    session = test_session();
    if(!session)
        return 1;

    for(stream = 0; stream <= 1; stream++) {
        channel = test_channel(session, local_id + (uint32_t)stream, 17,
                               64, 128);
        if(!channel) {
            err++;
            break;
        }

        if(stream)
            pkt_len = make_extended_data(pkt, channel->local.id, 1,
                                         payload, 64);
        else
            pkt_len = make_channel_data(pkt, channel->local.id,
                                        payload, 64, 64);

        rc = feed(session, pkt, pkt_len);
        if(rc != 0 || channel->read_avail != 64) {
            fprintf(stderr, "read_retry/%d: feed rc=%d read_avail=%lu\n",
                    stream, rc, (unsigned long)channel->read_avail);
            err++;
        }

        /* the read wants to grow the window first, but the adjust
           would block */
        wire_reset();
        send_would_block = 1;
        n = ssh2_channel_read(channel, stream, (char *)buf, 64);
        if(n != LIBSSH2_ERROR_EAGAIN) {
            fprintf(stderr, "read_retry/%d: first read n=%ld (want %d)\n",
                    stream, (long)n, LIBSSH2_ERROR_EAGAIN);
            err++;
        }
        if(channel->remote.window_size != 64 || channel->read_avail != 64) {
            fprintf(stderr, "read_retry/%d: accounting moved during "
                    "EAGAIN: window=%u read_avail=%lu\n",
                    stream, channel->remote.window_size,
                    (unsigned long)channel->read_avail);
            err++;
        }

        send_would_block = 0;
        n = ssh2_channel_read(channel, stream, (char *)buf, 64);
        if(n != 64 || memcmp(buf, payload, 64)) {
            fprintf(stderr, "read_retry/%d: retry read n=%ld (want 64)\n",
                    stream, (long)n);
            err++;
        }

        window_after[stream] = channel->remote.window_size;
        avail_after[stream] = channel->read_avail;

        adjusts = wire_window_adjusts(&adjust_total);
        if(adjusts != 1 || adjust_total != LIBSSH2_CHANNEL_MINADJUST) {
            fprintf(stderr, "read_retry/%d: wire adjusts=%d total=%u "
                    "(want 1/%d)\n",
                    stream, adjusts, adjust_total, LIBSSH2_CHANNEL_MINADJUST);
            err++;
        }

        if(test_channel_free(channel))
            err++;
    }

    /* normal and extended data must keep the same books */
    if(window_after[0] != window_after[1] ||
       avail_after[0] != avail_after[1]) {
        fprintf(stderr, "read_retry: stream accounting differs: "
                "window %u vs %u, avail %lu vs %lu\n",
                window_after[0], window_after[1],
                (unsigned long)avail_after[0], (unsigned long)avail_after[1]);
        err++;
    }
    if(window_after[0] != LIBSSH2_CHANNEL_MINADJUST ||
       avail_after[0] != 0) {
        fprintf(stderr, "read_retry: window=%u read_avail=%lu "
                "(want %d/0)\n",
                window_after[0], (unsigned long)avail_after[0],
                LIBSSH2_CHANNEL_MINADJUST);
        err++;
    }

    libssh2_session_free(session);

    return err > 0;
}

/*
 * Packets that arrive after a channel was closed are dropped: they must
 * not resurrect the closed channel, and their bytes must not be delivered
 * to a different (new) channel.
 */
static int test_late_packets_after_close(void)
{
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    LIBSSH2_CHANNEL *channel2;
    unsigned char pkt[13 + 20];
    unsigned char payload[20];
    unsigned char buf[20];
    static const unsigned char new_payload[7] = {
        'n', 'e', 'w', 'd', 'a', 't', 'a'
    };
    size_t pkt_len;
    ssize_t n;
    int rc;
    int err = 0;
    int i;

    for(i = 0; i < 20; i++)
        payload[i] = (unsigned char)(0x30 + i);

    session = test_session();
    channel = session ? test_channel(session, 0, 17, 128, 256) : NULL;
    if(!channel) {
        fprintf(stderr, "late_packets: setup failed\n");
        return 1;
    }

    pkt_len = make_channel_data(pkt, 0, payload, 5, 5);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0 || channel->read_avail != 5) {
        fprintf(stderr, "late_packets: initial feed rc=%d\n", rc);
        err++;
    }

    /* close and free the channel; the close packet goes on the wire */
    wire_reset();
    rc = test_channel_free(channel);
    if(rc != 0) {
        fprintf(stderr, "late_packets: channel free rc=%d\n", rc);
        err++;
    }
    if(ssh2_channel_locate(session, 0)) {
        fprintf(stderr, "late_packets: channel still listed after free\n");
        err++;
    }

    /* late data for the closed channel: dropped, nothing queued */
    pkt_len = make_channel_data(pkt, 0, payload, 20, 20);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0 || packets_queued(session)) {
        fprintf(stderr, "late_packets: late data rc=%d queued=%d\n",
                rc, packets_queued(session));
        err++;
    }
    if(libssh2_session_last_errno(session) !=
       LIBSSH2_ERROR_CHANNEL_UNKNOWN) {
        fprintf(stderr, "late_packets: last errno=%d (want %d)\n",
                libssh2_session_last_errno(session),
                LIBSSH2_ERROR_CHANNEL_UNKNOWN);
        err++;
    }

    /* late extended data for the closed channel: dropped as well */
    pkt_len = make_extended_data(pkt, 0, 1, payload, 20);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0 || packets_queued(session)) {
        fprintf(stderr, "late_packets: late ext data rc=%d queued=%d\n",
                rc, packets_queued(session));
        err++;
    }

    /* late EOF for the closed channel: quietly ignored */
    {
        unsigned char eof_pkt[5];
        unsigned char *s = eof_pkt;
        *s++ = SSH_MSG_CHANNEL_EOF;
        ssh2_store_u32(&s, 0);
        rc = feed(session, eof_pkt, sizeof(eof_pkt));
        if(rc != 0 || packets_queued(session)) {
            fprintf(stderr, "late_packets: late EOF rc=%d queued=%d\n",
                    rc, packets_queued(session));
            err++;
        }
    }

    /* the closed channel must not have come back */
    if(ssh2_channel_locate(session, 0)) {
        fprintf(stderr, "late_packets: closed channel resurrected\n");
        err++;
    }

    /* a new channel gets only its own bytes, none of the late ones */
    channel2 = test_channel(session, 1, 18, 128, 256);
    if(!channel2) {
        libssh2_session_free(session);
        return 1;
    }
    pkt_len = make_channel_data(pkt, 1, new_payload, 7, 7);
    rc = feed(session, pkt, pkt_len);
    if(rc != 0 || channel2->read_avail != 7) {
        fprintf(stderr, "late_packets: new channel rc=%d read_avail=%lu\n",
                rc, (unsigned long)channel2->read_avail);
        err++;
    }
    n = ssh2_channel_read(channel2, 0, (char *)buf, sizeof(buf));
    if(n != 7 || memcmp(buf, new_payload, 7)) {
        fprintf(stderr, "late_packets: new channel read n=%ld (want 7)\n",
                (long)n);
        err++;
    }
    if(test_channel_free(channel2))
        err++;
    libssh2_session_free(session);

    return err > 0;
}

int main(void)
{
    int rc;

    rc = libssh2_init(0);
    if(rc) {
        fprintf(stderr, "libssh2_init() failed: %d\n", rc);
        return 1;
    }

    rc = 0;
    rc |= test_window_adjust_bounds();
    rc |= test_channel_data_exceeds_window();
    rc |= test_channel_data_exceeds_packet_size();
    rc |= test_channel_data_inner_length_lies();
    rc |= test_extended_data_ignored();
    rc |= test_extended_data_ignored_eagain_retry();
    rc |= test_read_retry_accounting();
    rc |= test_late_packets_after_close();

    libssh2_exit();

    if(rc)
        fprintf(stderr, "test_channel_window: FAILURES\n");

    return rc;
}
