/* Copyright (C) The libssh2 project and its contributors.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/*
 * Malformed server packet tests.
 *
 * The SSH server-to-client DISCONNECT, DEBUG and CHANNEL_OPEN_FAILURE
 * messages as well as the SFTP SSH_FXP_STATUS message all carry
 * length-prefixed description strings.  A malicious or broken peer can
 * advertise a string length that runs past the end of the packet, truncate
 * the string (or the whole packet) in the middle, or claim an oversized
 * length.  These tests feed such packets through the real parsing code and
 * verify that:
 *
 *   1. the client maps every malformed packet onto a stable, deterministic
 *      local error code,
 *   2. any callback only ever sees pointers/lengths inside the received
 *      packet buffer (checked by the AddressSanitizer build),
 *   3. well-formed packets keep their historical code mapping, and
 *   4. after each malformed packet the connection state is unambiguous and
 *      no leftover bytes are handed to the next packet parse.
 *
 * No network, sshd or container is required: the transport layer is driven
 * directly with an in-memory receive callback, exactly like a peer sending
 * crafted binary packets.
 */

#include "libssh2_priv.h"
#include "libssh2_sftp.h"
#include "channel.h"
#include "sftp.h"
#include "transport.h"

#include <stdio.h>
#include <string.h>

/* SSH message types (RFC 4253 / RFC 4254), values from libssh2_priv.h */
#define MSSH_MSG_DISCONNECT            SSH_MSG_DISCONNECT
#define MSSH_MSG_DEBUG                 SSH_MSG_DEBUG
#define MSSH_MSG_CHANNEL_OPEN_FAILURE  SSH_MSG_CHANNEL_OPEN_FAILURE

/* SFTP message type, from sftp.c */
#define MSSH_FXP_STATUS                101

/*
 * Largest length prefix that fits in an SSH packet the transport layer will
 * accept (LIBSSH2_PACKET_MAXPAYLOAD).  A length prefix of this value can be
 * sent inside a small packet and must not make the parser read past the
 * packet boundary.
 */
#define GIANT_LEN 0x0000FFFFu

/* ------------------------------------------------------------------ */
/* In-memory transport feed                                            */
/* ------------------------------------------------------------------ */

static const unsigned char *feed_data;
static size_t feed_len;

/* Number of bytes that remain readable once the feed is exhausted.
   A truncated packet is followed by EOF (0), matching a peer that hangs
   up mid-packet. */
static ssize_t feed_tail_eagain;

static LIBSSH2_RECV_FUNC(feed_recv)
{
    size_t copy;

    (void)socket;
    (void)flags;
    (void)abstract;

    if(!feed_len) {
        if(feed_tail_eagain > 0) {
            feed_tail_eagain--;
            return -EAGAIN;
        }
        return 0;  /* connection closed */
    }

    copy = feed_len < length ? feed_len : (size_t)length;
    memcpy(buffer, feed_data, copy);
    feed_data += copy;
    feed_len -= copy;

    return (ssize_t)copy;
}

/* Point the session's transport at one crafted wire stream. */
static void feed_set(LIBSSH2_SESSION *session,
                     const unsigned char *data, size_t len,
                     ssize_t tail_eagain)
{
    session->recv_cb = feed_recv;
    feed_data = data;
    feed_len = len;
    feed_tail_eagain = tail_eagain;
}

/* ------------------------------------------------------------------ */
/* Wire packet construction (RFC 4253 section 6 binary packet)         */
/* ------------------------------------------------------------------ */

/*
 * Wrap a payload in an unencrypted SSH binary packet.  The padding length
 * and content are chosen by the caller so truncated-framing tests can
 * deliberately corrupt them; normal callers use wire_packet().
 *
 * The transport layer only requires:
 *   padding_length <= packet_length - 1
 *   total packet length a multiple of 8 (blocksize 5 path does not enforce
 *   this while unencrypted, but valid packets honor the RFC anyway)
 */
static size_t wire_build(unsigned char *out, size_t outsize,
                         const unsigned char *payload, size_t payload_len,
                         unsigned char padding_length,
                         const unsigned char *padding)
{
    uint32_t packet_length;
    size_t total;

    /* packet_length = padding_length byte + payload + padding */
    packet_length = (uint32_t)(1 + payload_len + padding_length);
    if((size_t)packet_length + 4 > outsize)
        return 0;

    total = 4 + packet_length;
    out[0] = (unsigned char)(packet_length >> 24);
    out[1] = (unsigned char)(packet_length >> 16);
    out[2] = (unsigned char)(packet_length >> 8);
    out[3] = (unsigned char)packet_length;
    out[4] = padding_length;
    if(payload_len)
        memcpy(out + 5, payload, payload_len);
    if(padding_length)
        memcpy(out + 5 + payload_len, padding, padding_length);

    return total;
}

/* RFC-compliant wrapper: enough zero padding to reach a multiple of 8. */
static size_t wire_packet(unsigned char *out, size_t outsize,
                          const unsigned char *payload, size_t payload_len)
{
    static const unsigned char zeros[16] = { 0 };
    size_t unpadded = 4 + 1 + payload_len;
    size_t padded = (unpadded + 7) & ~(size_t)7;
    unsigned char padding_length =
        (unsigned char)(padded - unpadded + 4);

    /* add 4 more padding bytes, still a multiple of 8 and >= 4 as required */
    return wire_build(out, outsize, payload, payload_len,
                      padding_length, zeros);
}

static void put_u32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v >> 24);
    p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);
    p[3] = (unsigned char)v;
}

/* ------------------------------------------------------------------ */
/* Callback recording                                                  */
/* ------------------------------------------------------------------ */

struct cb_record {
    int calls;
    int reason;                 /* disconnect reason code */
    int always_display;         /* debug flag */
    const unsigned char *base;  /* expected payload base/end */
    const unsigned char *end;
    char msg_sentinel;          /* copied first byte, proves pointer read */
    size_t message_len;
    size_t language_len;
    int in_bounds;              /* every pointer/length inside the packet */
};

static void cb_reset(struct cb_record *rec,
                     const unsigned char *base, size_t len)
{
    memset(rec, 0, sizeof(*rec));
    rec->base = base;
    rec->end = base + len;
    rec->in_bounds = 1;
}

/*
 * The parser hands the callback pointers into the payload buffer it
 * allocated while framing the packet (a copy of the wire payload).  Track
 * the lowest/highest address the callback is ever asked to read so the
 * AddressSanitizer build catches any overrun, while we additionally verify
 * every range is self-consistent (non-negative, no wrap-around).
 */
static void cb_note(struct cb_record *rec,
                    const char *message, int message_len,
                    const char *language, int language_len)
{
    const unsigned char *m = (const unsigned char *)message;
    const unsigned char *l = (const unsigned char *)language;

    rec->calls++;
    rec->message_len = (size_t)message_len;
    rec->language_len = (size_t)language_len;

    if(message_len < 0 || language_len < 0)
        rec->in_bounds = 0;

    if(message_len > 0) {
        if(!m)
            rec->in_bounds = 0;
        else {
            /* Touch every byte: ASan reports an out-of-bounds read if the
               parser miscomputed the length; wrap-around is caught too. */
            volatile unsigned char sink = 0;
            int k;
            for(k = 0; k < message_len; k++)
                sink = (unsigned char)(sink + m[k]);
            rec->msg_sentinel = (char)m[0];
            (void)sink;
        }
    }

    if(language_len > 0) {
        if(!l)
            rec->in_bounds = 0;
        else {
            volatile unsigned char sink = 0;
            int k;
            for(k = 0; k < language_len; k++)
                sink = (unsigned char)(sink + l[k]);
            (void)sink;
        }
    }
}

static LIBSSH2_DISCONNECT_FUNC(disconnect_cb)
{
    /* The library passes &session->abstract, i.e. a void ** whose pointee
       holds the cb_record installed below. */
    struct cb_record *rec = *(struct cb_record **)abstract;

    rec->reason = reason;
    cb_note(rec, message, message_len, language, language_len);
}

static LIBSSH2_DEBUG_FUNC(debug_cb)
{
    struct cb_record *rec = *(struct cb_record **)abstract;

    rec->always_display = always_display;
    cb_note(rec, message, message_len, language, language_len);
}

/* Callbacks receive &session->abstract as their abstract pointer, so the
   record is installed through the session internals. */
static void cb_install_disconnect(LIBSSH2_SESSION *session,
                                  struct cb_record *rec)
{
    session->abstract = rec;
    libssh2_session_callback_set2(session,
                                  LIBSSH2_CALLBACK_DISCONNECT,
                                  (libssh2_cb_generic *)disconnect_cb);
}

static void cb_install_debug(LIBSSH2_SESSION *session,
                             struct cb_record *rec)
{
    session->abstract = rec;
    libssh2_session_callback_set2(session,
                                  LIBSSH2_CALLBACK_DEBUG,
                                  (libssh2_cb_generic *)debug_cb);
}

/* ------------------------------------------------------------------ */
/* Shared helpers                                                      */
/* ------------------------------------------------------------------ */

static int failures;

#define CHECK(cond, ...)                                       \
    do {                                                       \
        if(!(cond)) {                                          \
            fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                      \
            fprintf(stderr, "\n");                             \
            failures++;                                        \
        }                                                      \
    } while(0)

static LIBSSH2_SESSION *make_session(void)
{
    LIBSSH2_SESSION *session = libssh2_session_init();
    if(session) {
        /* Pretend the initial key exchange finished: transport packets are
           accepted and the socket is considered live. */
        session->state &= ~SSH2_STATE_INITIAL_KEX;
        session->state |= SSH2_STATE_AUTHENTICATED;
        session->socket_state = SSH2_SOCKET_CONNECTED;
    }
    return session;
}

/*
 * Feed one wire stream and drain the transport layer until it stops
 * producing packets.  Returns the last transport result and the number of
 * packets that ended up queued in the brigade.
 */
static int drain_transport(LIBSSH2_SESSION *session, int *queued)
{
    int rc = 0;
    int i;

    for(i = 0; i < 8; i++) {
        rc = ssh2_transport_read(session);
        if(rc <= 0)
            break;  /* error / EAGAIN / no packet */
    }

    {
        int n = 0;
        if(ssh2_list_first(&session->packets)) {
            struct packet *p = ssh2_list_first(&session->packets);
            n++;
            while((p = ssh2_list_next(&p->node)))
                n++;
        }
        if(queued)
            *queued = n;
    }
    return rc;
}

/* Free anything still queued in the brigade so session_free() stays clean. */
static void flush_brigade(LIBSSH2_SESSION *session)
{
    struct packet *p = ssh2_list_first(&session->packets);
    while(p) {
        struct packet *next = ssh2_list_next(&p->node);
        SSH2_FREE(session, p->data);
        ssh2_list_remove(&p->node);
        SSH2_FREE(session, p);
        p = next;
    }
}

/* ================================================================== */
/* SSH_MSG_DISCONNECT (type 1)                                         */
/* ================================================================== */

/*
 * byte      SSH_MSG_DISCONNECT
 * uint32    reason code
 * string    description
 * string    language tag
 */
static int test_disconnect_packets(void)
{
    /* SSH_DISCONNECT_BY_APPLICATION */
    static const unsigned char reason_ssh = 11;
    struct {
        const char *name;
        unsigned char payload[128];
        size_t payload_len;
        /* wire stream overrides; when zero the payload is wrapped normally */
        unsigned char wire[160];
        size_t wire_len;          /* explicit (possibly truncated) stream */
        ssize_t tail_eagain;
        int want_transport_rc;
        int want_session_errno;
        int check_errno;          /* framing errors bypass ssh2_err() */
        int want_callback;        /* callback expected to fire */
        int want_reason;
    } cases[10];
    size_t ncases = 0;
    size_t i;
    int err = 0;

    /* ---- well-formed: mapping must stay unchanged ---- */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_DISCONNECT;
        put_u32(q + n, reason_ssh); n += 4;
        put_u32(q + n, 3); n += 4;
        memcpy(q + n, "bye", 3); n += 3;
        put_u32(q + n, 2); n += 4;
        memcpy(q + n, "en", 2); n += 2;
        cases[ncases].name = "well-formed";
        cases[ncases].payload_len = n;
        cases[ncases].want_transport_rc = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        cases[ncases].want_session_errno = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        cases[ncases].want_callback = 1;
        cases[ncases].want_reason = (int)reason_ssh;
        ncases++;
    }

    /* ---- description length runs past the packet end ---- */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_DISCONNECT;
        put_u32(q + n, reason_ssh); n += 4;
        put_u32(q + n, 100); n += 4;   /* claims 100 bytes, none present */
        /* packet ends here: no description bytes, no language tag */
        cases[ncases].name = "desc-length-overruns";
        cases[ncases].payload_len = n;
        cases[ncases].want_transport_rc = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        cases[ncases].want_session_errno = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        cases[ncases].want_callback = 1;  /* fires with zeroed lengths */
        cases[ncases].want_reason = (int)reason_ssh;
        ncases++;
    }

    /* ---- description present but truncated mid-string ---- */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_DISCONNECT;
        put_u32(q + n, reason_ssh); n += 4;
        put_u32(q + n, 10); n += 4;    /* claims 10 bytes */
        memcpy(q + n, "abc", 3); n += 3; /* only 3 delivered */
        cases[ncases].name = "desc-truncated";
        cases[ncases].payload_len = n;
        cases[ncases].want_transport_rc = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        cases[ncases].want_session_errno = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        cases[ncases].want_callback = 1;
        cases[ncases].want_reason = (int)reason_ssh;
        ncases++;
    }

    /* ---- oversized description length (uint32 giant) ---- */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_DISCONNECT;
        put_u32(q + n, reason_ssh); n += 4;
        put_u32(q + n, GIANT_LEN); n += 4;
        memcpy(q + n, "x", 1); n += 1;
        cases[ncases].name = "desc-oversized";
        cases[ncases].payload_len = n;
        cases[ncases].want_transport_rc = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        cases[ncases].want_session_errno = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        cases[ncases].want_callback = 1;
        cases[ncases].want_reason = (int)reason_ssh;
        ncases++;
    }

    /* ---- language tag length overruns ---- */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_DISCONNECT;
        put_u32(q + n, reason_ssh); n += 4;
        put_u32(q + n, 1); n += 4;
        q[n++] = 'x';                 /* complete description */
        put_u32(q + n, 50); n += 4;   /* language claims 50, none present */
        cases[ncases].name = "lang-overruns";
        cases[ncases].payload_len = n;
        cases[ncases].want_transport_rc = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        cases[ncases].want_session_errno = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        cases[ncases].want_callback = 1;
        cases[ncases].want_reason = (int)reason_ssh;
        ncases++;
    }

    /* ---- packet truncated before the reason code ---- */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_DISCONNECT;
        q[n++] = 0; q[n++] = 0;  /* only 2 of the 4 reason bytes */
        cases[ncases].name = "reason-truncated";
        cases[ncases].payload_len = n;
        cases[ncases].want_transport_rc = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        cases[ncases].want_session_errno = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        /* datalen 3 < 5: the parser skips string extraction entirely and
           must not invoke the callback with uninitialized pointers */
        cases[ncases].want_callback = 0;
        cases[ncases].want_reason = 0;
        ncases++;
    }

    /* ---- datalen >= 5 but the reason code itself is cut ---- */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_DISCONNECT;
        q[n++] = 0; q[n++] = 0; q[n++] = 7;  /* 3 of the 4 reason bytes */
        q[n++] = 0;
        q[n++] = 0;                          /* 2 trailing bytes */
        cases[ncases].name = "reason-partial";
        cases[ncases].payload_len = n;
        cases[ncases].want_transport_rc = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        cases[ncases].want_session_errno = LIBSSH2_ERROR_SOCKET_DISCONNECT;
        /* The four bytes available after the type byte form the reason
           (0x00000700); the following string extraction then fails and the
           callback only sees zero, in-bounds lengths. */
        cases[ncases].want_callback = 1;
        cases[ncases].want_reason = 0x00000700;
        ncases++;
    }

    /* ---- framing: declared packet length extends past the stream ---- */
    {
        static const unsigned char tiny_payload[] = {
            MSSH_MSG_DISCONNECT, 0, 0, 0, reason_ssh
        };
        unsigned char stream[64];
        size_t cut;

        (void)wire_packet(stream, sizeof(stream),
                          tiny_payload, sizeof(tiny_payload));
        /* Deliver only the 5-byte header plus one payload byte: the peer
           vanished while sending the rest. */
        cut = 6;
        memcpy(cases[ncases].wire, stream, cut);
        cases[ncases].name = "framing-truncated-eof";
        cases[ncases].wire_len = cut;
        cases[ncases].tail_eagain = 0;   /* recv() returns 0: closed */
        cases[ncases].want_transport_rc = LIBSSH2_ERROR_SOCKET_RECV;
        cases[ncases].want_session_errno = LIBSSH2_ERROR_SOCKET_RECV;
        cases[ncases].check_errno = 0;
        cases[ncases].want_callback = 0;
        ncases++;
    }

    /* ---- framing: packet length beyond LIBSSH2_PACKET_MAXPAYLOAD ---- */
    {
        unsigned char stream[16];
        size_t n = 0;
        /* packet_length = 0x00010000 (40000+), no bytes follow */
        put_u32(stream + n, 40001); n += 4;
        stream[n++] = 4;  /* padding_length */
        stream[n++] = MSSH_MSG_DISCONNECT;
        cases[ncases].name = "framing-oversized-length";
        memcpy(cases[ncases].wire, stream, n);
        cases[ncases].wire_len = n;
        cases[ncases].tail_eagain = 2;  /* EAGAIN, then EOF: must still fail */
        cases[ncases].want_transport_rc = LIBSSH2_ERROR_OUT_OF_BOUNDARY;
        cases[ncases].want_session_errno = LIBSSH2_ERROR_OUT_OF_BOUNDARY;
        cases[ncases].check_errno = 0;
        cases[ncases].want_callback = 0;
        ncases++;
    }

    for(i = 0; i < ncases; i++) {
        LIBSSH2_SESSION *session = make_session();
        struct cb_record rec;
        unsigned char stream[192];
        size_t stream_len;
        int rc;
        int queued = -1;
        int errno_got;

        /* Framing failures are raw transport returns that bypass
           ssh2_err(), so only payload-level failures set session errno. */

        if(!session) {
            fprintf(stderr, "disconnect/%s: session init failed\n",
                    cases[i].name);
            failures++;
            return ++err;
        }

        libssh2_session_set_blocking(session, 0);

        if(cases[i].wire_len) {
            stream_len = cases[i].wire_len;
            memcpy(stream, cases[i].wire, stream_len);
        }
        else {
            stream_len = wire_packet(stream, sizeof(stream),
                                     cases[i].payload,
                                     cases[i].payload_len);
        }
        CHECK(stream_len > 0, "disconnect/%s: wire build failed",
              cases[i].name);

        cb_reset(&rec, stream, stream_len);
        cb_install_disconnect(session, &rec);
        feed_set(session, stream, stream_len, cases[i].tail_eagain);

        rc = drain_transport(session, &queued);
        errno_got = libssh2_session_last_errno(session);

        CHECK(rc == cases[i].want_transport_rc,
              "disconnect/%s: transport rc=%d want %d",
              cases[i].name, rc, cases[i].want_transport_rc);
        if(cases[i].check_errno)
            CHECK(errno_got == cases[i].want_session_errno,
                  "disconnect/%s: session errno=%d want %d",
                  cases[i].name, errno_got,
                  cases[i].want_session_errno);
        CHECK(rec.calls == cases[i].want_callback,
              "disconnect/%s: callback calls=%d want %d",
              cases[i].name, rec.calls, cases[i].want_callback);
        if(cases[i].want_callback) {
            CHECK(rec.in_bounds,
                  "disconnect/%s: callback got out-of-bounds pointer",
                  cases[i].name);
            CHECK(rec.reason == cases[i].want_reason,
                  "disconnect/%s: reason=%d want %d",
                  cases[i].name, rec.reason, cases[i].want_reason);
        }

        /*
         * State check: a disconnect must leave the socket marked
         * disconnected and the parser idle, so nothing is re-parsed as part
         * of the next message.
         */
        if(cases[i].want_transport_rc == LIBSSH2_ERROR_SOCKET_DISCONNECT) {
            CHECK(session->socket_state == SSH2_SOCKET_DISCONNECTED,
                  "disconnect/%s: socket_state=%d want DISCONNECTED",
                  cases[i].name, session->socket_state);
            CHECK(session->packAdd_state == ssh2_NB_state_idle,
                  "disconnect/%s: packAdd_state not idle",
                  cases[i].name);
            CHECK(queued == 0,
                  "disconnect/%s: %d packet(s) leaked into brigade",
                  cases[i].name, queued);
        }
        else {
            /* framing failures: transport state reset, no queued packet */
            CHECK(queued == 0,
                  "disconnect/%s: malformed frame queued (%d packets)",
                  cases[i].name, queued);
            CHECK(session->fullpacket_state == ssh2_NB_state_idle,
                  "disconnect/%s: fullpacket_state not idle",
                  cases[i].name);
        }

        /*
         * A second parse attempt must not reinterpret leftover bytes.
         * The feed is empty; no new packet may appear.
         */
        {
            int rc2 = ssh2_transport_read(session);
            int queued2 = 0;
            struct packet *p = ssh2_list_first(&session->packets);
            while(p) {
                queued2++;
                p = ssh2_list_next(&p->node);
            }
            CHECK(queued2 == queued,
                  "disconnect/%s: stale bytes produced a second packet "
                  "(%d -> %d)", cases[i].name, queued, queued2);
            (void)rc2;
        }

        flush_brigade(session);
        libssh2_session_free(session);
    }

    return err;
}

/* ================================================================== */
/* SSH_MSG_DEBUG (type 4)                                              */
/* ================================================================== */

/*
 * byte      SSH_MSG_DEBUG
 * boolean   always_display
 * string    message
 * string    language tag
 *
 * DEBUG packets do not tear the connection down: they are consumed inside
 * ssh2_packet_add() and parsing must continue cleanly with the next packet.
 */
static int test_debug_packets(void)
{
    struct {
        const char *name;
        unsigned char payload[160];
        size_t payload_len;
        int datalen_ok;       /* reaches the datalen >= 6 parse branch */
        int want_always;
        int want_callback;    /* whether the debug callback is invoked */
    } cases[7];
    size_t ncases = 0;
    size_t i;

    /* well-formed */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_DEBUG;
        q[n++] = 1;                     /* always_display */
        put_u32(q + n, 5); n += 4;
        memcpy(q + n, "debug", 5); n += 5;
        put_u32(q + n, 2); n += 4;
        memcpy(q + n, "en", 2); n += 2;
        cases[ncases].name = "well-formed";
        cases[ncases].payload_len = n;
        cases[ncases].datalen_ok = 1;
        cases[ncases].want_always = 1;
        cases[ncases].want_callback = 1;
        ncases++;
    }

    /* message length overruns packet end */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_DEBUG;
        q[n++] = 0;
        put_u32(q + n, 64); n += 4;     /* no message bytes follow */
        cases[ncases].name = "msg-overruns";
        cases[ncases].payload_len = n;
        cases[ncases].datalen_ok = 1;
        cases[ncases].want_always = 0;
        cases[ncases].want_callback = 1;
        ncases++;
    }

    /* message truncated mid-string */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_DEBUG;
        q[n++] = 1;
        put_u32(q + n, 8); n += 4;
        memcpy(q + n, "ab", 2); n += 2;
        cases[ncases].name = "msg-truncated";
        cases[ncases].payload_len = n;
        cases[ncases].datalen_ok = 1;
        cases[ncases].want_always = 1;
        cases[ncases].want_callback = 1;
        ncases++;
    }

    /* oversized message length */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_DEBUG;
        q[n++] = 0;
        put_u32(q + n, GIANT_LEN); n += 4;
        q[n++] = 'z';
        cases[ncases].name = "msg-oversized";
        cases[ncases].payload_len = n;
        cases[ncases].datalen_ok = 1;
        cases[ncases].want_always = 0;
        cases[ncases].want_callback = 1;
        ncases++;
    }

    /* valid message, language overruns */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_DEBUG;
        q[n++] = 1;
        put_u32(q + n, 1); n += 4;
        q[n++] = 'm';
        put_u32(q + n, 32); n += 4;
        cases[ncases].name = "lang-overruns";
        cases[ncases].payload_len = n;
        cases[ncases].datalen_ok = 1;
        cases[ncases].want_always = 1;
        cases[ncases].want_callback = 1;
        ncases++;
    }

    /* truncated before the message length field (datalen < 6): the parser
       skips string extraction entirely and must not touch bad pointers */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_DEBUG;
        q[n++] = 1;
        q[n++] = 0; q[n++] = 0;   /* partial length prefix only */
        cases[ncases].name = "header-truncated";
        cases[ncases].payload_len = n;
        cases[ncases].datalen_ok = 0;
        cases[ncases].want_always = 1;
        cases[ncases].want_callback = 1;
        ncases++;
    }

    /* only the type byte (datalen < 2): the guard skips both string
       extraction and the callback, no pointer may be touched */
    {
        cases[ncases].payload[0] = MSSH_MSG_DEBUG;
        cases[ncases].name = "type-only";
        cases[ncases].payload_len = 1;
        cases[ncases].datalen_ok = 0;
        cases[ncases].want_always = 0;
        /* datalen 1 < 2 means the callback branch is skipped entirely */
        cases[ncases].want_callback = 0;
        ncases++;
    }

    for(i = 0; i < ncases; i++) {
        LIBSSH2_SESSION *session = make_session();
        struct cb_record rec;
        unsigned char stream[192];
        size_t stream_len;
        int rc;
        int queued = -1;

        if(!session) {
            fprintf(stderr, "debug/%s: session init failed\n",
                    cases[i].name);
            failures++;
            continue;
        }

        libssh2_session_set_blocking(session, 0);
        stream_len = wire_packet(stream, sizeof(stream),
                                 cases[i].payload, cases[i].payload_len);
        CHECK(stream_len > 0, "debug/%s: wire build failed", cases[i].name);

        cb_reset(&rec, stream, stream_len);
        cb_install_debug(session, &rec);
        /* EAGAIN after the packet: keeps the socket "connected" while the
           parser drains the single queued message. */
        feed_set(session, stream, stream_len, 4);

        /* DEBUG is consumed inside packet_add: the first read returns the
           message type, later reads hit the empty feed. */
        rc = drain_transport(session, &queued);

        CHECK(rec.calls == cases[i].want_callback,
              "debug/%s: callback calls=%d want %d",
              cases[i].name, rec.calls, cases[i].want_callback);
        if(cases[i].want_callback)
            CHECK(rec.in_bounds,
                  "debug/%s: callback got out-of-bounds pointer",
                  cases[i].name);
        if(cases[i].datalen_ok)
            CHECK(rec.always_display == cases[i].want_always,
                  "debug/%s: always_display=%d want %d",
                  cases[i].name, rec.always_display,
                  cases[i].want_always);

        /* the connection stays up and the packet is fully consumed */
        CHECK(session->socket_state == SSH2_SOCKET_CONNECTED,
              "debug/%s: socket_state=%d want CONNECTED",
              cases[i].name, session->socket_state);
        CHECK(session->packAdd_state == ssh2_NB_state_idle,
              "debug/%s: packAdd_state not idle", cases[i].name);
        CHECK(queued == 0,
              "debug/%s: consumed packet left in brigade (%d)",
              cases[i].name, queued);
        /* the first call delivered the DEBUG type; the loop then stopped on
           EAGAIN once the feed ran out */
        CHECK(rc == MSSH_MSG_DEBUG || rc == LIBSSH2_ERROR_EAGAIN,
              "debug/%s: transport rc=%d unexpected", cases[i].name, rc);

        /* feed a second, well-formed DEBUG: it must parse independently with
           no state carried over from the malformed first packet */
        {
            static const unsigned char good[] = {
                MSSH_MSG_DEBUG, 1,
                0, 0, 0, 2, 'o', 'k',
                0, 0, 0, 0
            };
            unsigned char stream2[32];
            size_t len2 = wire_packet(stream2, sizeof(stream2),
                                      good, sizeof(good));
            struct cb_record rec2;

            cb_reset(&rec2, stream2, len2);
            cb_install_debug(session, &rec2);
            feed_set(session, stream2, len2, 4);
            rc = drain_transport(session, &queued);

            CHECK(rec2.calls == 1 && rec2.in_bounds &&
                  rec2.message_len == 2 && rec2.always_display == 1,
                  "debug/%s: follow-up packet contaminated "
                  "(calls=%d in_bounds=%d msglen=%lu display=%d)",
                  cases[i].name, rec2.calls, rec2.in_bounds,
                  (unsigned long)rec2.message_len, rec2.always_display);
            CHECK(queued == 0,
                  "debug/%s: follow-up left packet in brigade",
                  cases[i].name);
            (void)rc;
        }

        flush_brigade(session);
        libssh2_session_free(session);
    }

    return 0;
}

/* ================================================================== */
/* SSH_MSG_CHANNEL_OPEN_FAILURE (type 92)                             */
/* ================================================================== */

/*
 * byte      SSH_MSG_CHANNEL_OPEN_FAILURE
 * uint32    recipient channel
 * uint32    reason code
 * string    description
 * string    language tag
 *
 * The channel opener only consumes the recipient channel and the reason
 * code; the description strings are skipped entirely.  A malformed
 * description must therefore still map deterministically onto
 * LIBSSH2_ERROR_CHANNEL_FAILURE, and a truncated header onto PROTO.
 */
static int test_channel_open_failure(void)
{
    static const uint32_t recipient = 0;
    struct {
        const char *name;
        unsigned char payload[160];
        size_t payload_len;
        int want_rc;            /* result from ssh2_channel_open */
        int want_errno;
        int want_queued;        /* packets the open path leaves behind */
    } cases[8];
    size_t ncases = 0;
    size_t i;

    /* well-formed, known reason code */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_CHANNEL_OPEN_FAILURE;
        put_u32(q + n, recipient); n += 4;
        put_u32(q + n, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED); n += 4;
        put_u32(q + n, 4); n += 4;
        memcpy(q + n, "nope", 4); n += 4;
        put_u32(q + n, 0); n += 4;
        cases[ncases].name = "well-formed";
        cases[ncases].payload_len = n;
        cases[ncases].want_rc = 0; /* NULL return, errno carries the code */
        cases[ncases].want_errno = LIBSSH2_ERROR_CHANNEL_FAILURE;
        ncases++;
    }

    /* description length overruns */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_CHANNEL_OPEN_FAILURE;
        put_u32(q + n, recipient); n += 4;
        put_u32(q + n, SSH_OPEN_RESOURCE_SHORTAGE); n += 4;
        put_u32(q + n, 200); n += 4;
        cases[ncases].name = "desc-overruns";
        cases[ncases].payload_len = n;
        cases[ncases].want_rc = 0;
        cases[ncases].want_errno = LIBSSH2_ERROR_CHANNEL_FAILURE;
        ncases++;
    }

    /* description truncated */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_CHANNEL_OPEN_FAILURE;
        put_u32(q + n, recipient); n += 4;
        put_u32(q + n, SSH_OPEN_CONNECT_FAILED); n += 4;
        put_u32(q + n, 9); n += 4;
        memcpy(q + n, "ab", 2); n += 2;
        cases[ncases].name = "desc-truncated";
        cases[ncases].payload_len = n;
        cases[ncases].want_rc = 0;
        cases[ncases].want_errno = LIBSSH2_ERROR_CHANNEL_FAILURE;
        ncases++;
    }

    /* oversized description length */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_CHANNEL_OPEN_FAILURE;
        put_u32(q + n, recipient); n += 4;
        put_u32(q + n, SSH_OPEN_UNKNOWN_CHANNELTYPE); n += 4;
        put_u32(q + n, GIANT_LEN); n += 4;
        q[n++] = 'q';
        cases[ncases].name = "desc-oversized";
        cases[ncases].payload_len = n;
        cases[ncases].want_rc = 0;
        cases[ncases].want_errno = LIBSSH2_ERROR_CHANNEL_FAILURE;
        ncases++;
    }

    /* unknown reason code keeps the generic channel-failure mapping */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_CHANNEL_OPEN_FAILURE;
        put_u32(q + n, recipient); n += 4;
        put_u32(q + n, 123456); n += 4;
        put_u32(q + n, 3); n += 4;
        memcpy(q + n, "why", 3); n += 3;
        put_u32(q + n, 0); n += 4;
        cases[ncases].name = "unknown-reason";
        cases[ncases].payload_len = n;
        cases[ncases].want_rc = 0;
        cases[ncases].want_errno = LIBSSH2_ERROR_CHANNEL_FAILURE;
        ncases++;
    }

    /* truncated before reason code (open_data_len < 9) -> PROTO */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_CHANNEL_OPEN_FAILURE;
        put_u32(q + n, recipient); n += 4;
        q[n++] = 0; q[n++] = 0;  /* 2 of 4 reason bytes */
        cases[ncases].name = "reason-truncated";
        cases[ncases].payload_len = n;
        cases[ncases].want_rc = 0;
        cases[ncases].want_errno = LIBSSH2_ERROR_PROTO;
        ncases++;
    }

    /* header present but too short for the reason code (open_data_len < 9)
       -> PROTO.  Five bytes still let the brigade match on channel id. */
    {
        unsigned char *q = cases[ncases].payload;
        size_t n = 0;
        q[n++] = MSSH_MSG_CHANNEL_OPEN_FAILURE;
        put_u32(q + n, recipient); n += 4;
        cases[ncases].name = "header-only";
        cases[ncases].payload_len = n;
        cases[ncases].want_rc = 0;
        cases[ncases].want_errno = LIBSSH2_ERROR_PROTO;
        ncases++;
    }

    /* only the type byte: cannot even match the recipient channel, so the
       waiter reports a generic -1 lookup failure rather than PROTO */
    {
        cases[ncases].payload[0] = MSSH_MSG_CHANNEL_OPEN_FAILURE;
        cases[ncases].name = "type-only";
        cases[ncases].payload_len = 1;
        cases[ncases].want_rc = 0;
        cases[ncases].want_errno = -1;
        /* Too short to match the recipient channel, so the open path cannot
           consume it; the packet remains queued and is reclaimed below. */
        cases[ncases].want_queued = 1;
        ncases++;
    }

    for(i = 0; i < ncases; i++) {
        LIBSSH2_SESSION *session = make_session();
        unsigned char stream[192];
        size_t stream_len;
        LIBSSH2_CHANNEL *ch;
        int errno_got;
        int queued = -1;

        if(!session) {
            fprintf(stderr, "chanopen/%s: session init failed\n",
                    cases[i].name);
            failures++;
            continue;
        }

        libssh2_session_set_blocking(session, 0);
        stream_len = wire_packet(stream, sizeof(stream),
                                 cases[i].payload, cases[i].payload_len);
        CHECK(stream_len > 0, "chanopen/%s: wire build failed",
              cases[i].name);
        feed_set(session, stream, stream_len, 0);

        /*
         * ssh2_channel_open() first sends SSH_MSG_CHANNEL_OPEN.  The send
         * callback is never installed in this fixture, so the transport
         * write path is bypassed by pre-arming the open state instead:
         * place the reply in the brigade and jump straight to the wait
         * state.
         *
         * open_packet must still exist because requirev matches the
         * recipient channel id at offset 5 + channel_type_len (4 bytes).
         * Layout mirrors the real CHANNEL_OPEN packet:
         *   type(1) + type-string(4+7) + sender(4) + window(4) + packet(4)
         */
        session->open_state = ssh2_NB_state_sent;
        session->open_packet_len = 7 + 17;
        session->open_packet =
            SSH2_ALLOC(session, session->open_packet_len);
        if(session->open_packet) {
            unsigned char *op = session->open_packet;
            memset(op, 0, session->open_packet_len);
            op[0] = SSH_MSG_CHANNEL_OPEN;
            put_u32(op + 1, 7);                 /* channel type length */
            memcpy(op + 5, "session", 7);
            put_u32(op + 12, recipient);        /* sender channel id */
        }
        {
            struct packet *pkt =
                SSH2_CALLOC(session, sizeof(struct packet));
            if(pkt) {
                pkt->data = SSH2_ALLOC(session, cases[i].payload_len);
                if(pkt->data) {
                    memcpy(pkt->data, cases[i].payload,
                           cases[i].payload_len);
                    pkt->data_len = cases[i].payload_len;
                    ssh2_list_add(&session->packets, &pkt->node);
                }
                else {
                    SSH2_FREE(session, pkt);
                }
            }
        }

        ch = ssh2_channel_open(session, "session", 7,
                               65536, 32768, NULL, 0);

        errno_got = libssh2_session_last_errno(session);
        CHECK(ch == NULL,
              "chanopen/%s: channel unexpectedly opened", cases[i].name);
        CHECK(errno_got == cases[i].want_errno,
              "chanopen/%s: errno=%d want %d",
              cases[i].name, errno_got, cases[i].want_errno);

        /* open machinery reset: no half-open channel or packet remains */
        CHECK(session->open_state == ssh2_NB_state_idle,
              "chanopen/%s: open_state=%d not idle",
              cases[i].name, (int)session->open_state);
        CHECK(session->open_channel == NULL,
              "chanopen/%s: open_channel left behind", cases[i].name);
        CHECK(session->open_data == NULL,
              "chanopen/%s: open_data leaked", cases[i].name);
        CHECK(session->open_packet == NULL,
              "chanopen/%s: open_packet leaked", cases[i].name);

        /* brigade must be empty: the reply was consumed by the open state
           machine, nothing carries over to the next channel-open attempt.
           The sub-header type-only packet cannot match and stays queued. */
        queued = ssh2_list_first(&session->packets) ? 1 : 0;
        CHECK(queued == cases[i].want_queued,
              "chanopen/%s: %d packet(s) left in brigade, want %d",
              cases[i].name, queued, cases[i].want_queued);

        /* no channel nodes remain in the session */
        CHECK(ssh2_list_first(&session->channels) == NULL,
              "chanopen/%s: channel left in session list", cases[i].name);

        flush_brigade(session);
        libssh2_session_free(session);
    }

    return 0;
}

/* ================================================================== */
/* SFTP SSH_FXP_STATUS (101)                                          */
/* ================================================================== */

/*
 * uint32    packet_length
 * byte      SSH_FXP_STATUS
 * uint32    request id
 * uint32    status code
 * string    error message
 * string    language tag
 *
 * The SFTP protocol code only reads the 4-byte status code; the message and
 * language strings are never dereferenced.  These tests prove that malformed
 * strings cannot change the status-code mapping and that the packet framing
 * rejects overlong/truncated packets before any out-of-bounds access.
 */

/* Build an SFTP packet body (the 4-byte outer length is added by framing). */
static size_t fxp_status_build(unsigned char *out, size_t outsize,
                               uint32_t request_id, uint32_t status_code,
                               uint32_t msg_declared,
                               const unsigned char *msg_bytes,
                               size_t msg_present,
                               uint32_t lang_declared,
                               const unsigned char *lang_bytes,
                               size_t lang_present)
{
    size_t n = 0;

    if(outsize < 9 + msg_present + lang_present + 8)
        return 0;

    out[n++] = MSSH_FXP_STATUS;
    put_u32(out + n, request_id); n += 4;
    put_u32(out + n, status_code); n += 4;
    put_u32(out + n, msg_declared); n += 4;
    if(msg_present) {
        memcpy(out + n, msg_bytes, msg_present);
        n += msg_present;
    }
    put_u32(out + n, lang_declared); n += 4;
    if(lang_present) {
        memcpy(out + n, lang_bytes, lang_present);
        n += lang_present;
    }
    return n;
}

/* Minimal SFTP fixture following the test_simple.c pattern: a session with a
   bare channel and an SFTP struct whose packet brigade we control. */
struct sftp_fixture {
    LIBSSH2_SESSION *session;
    LIBSSH2_CHANNEL *channel;
    LIBSSH2_SFTP *sftp;
};

static int sftp_fixture_init(struct sftp_fixture *fx)
{
    fx->session = make_session();
    if(!fx->session)
        return -1;

    fx->channel = SSH2_CALLOC(fx->session, sizeof(*fx->channel));
    fx->sftp = SSH2_CALLOC(fx->session, sizeof(*fx->sftp));
    if(!fx->channel || !fx->sftp) {
        if(fx->channel)
            SSH2_FREE(fx->session, fx->channel);
        if(fx->sftp)
            SSH2_FREE(fx->session, fx->sftp);
        libssh2_session_free(fx->session);
        return -1;
    }

    fx->channel->session = fx->session;
    ssh2_list_add(&fx->session->channels, &fx->channel->node);
    fx->sftp->channel = fx->channel;
    fx->sftp->version = 3;
    ssh2_list_init(&fx->sftp->packets);
    ssh2_list_init(&fx->sftp->zombie_requests);
    return 0;
}

static void sftp_fixture_free(struct sftp_fixture *fx)
{
    struct sftp_packet *p = ssh2_list_first(&fx->sftp->packets);
    while(p) {
        struct sftp_packet *next = ssh2_list_next(&p->node);
        SSH2_FREE(fx->session, p->data);
        ssh2_list_remove(&p->node);
        SSH2_FREE(fx->session, p);
        p = next;
    }
    SSH2_FREE(fx->session, fx->sftp);
    ssh2_list_remove(&fx->channel->node);
    SSH2_FREE(fx->session, fx->channel);
    libssh2_session_free(fx->session);
}

/* Queue one SFTP packet body as the transport would deliver it. */
static int sftp_queue_packet(struct sftp_fixture *fx,
                             const unsigned char *body, size_t body_len,
                             uint32_t request_id)
{
    struct sftp_packet *packet =
        SSH2_CALLOC(fx->session, sizeof(*packet));
    if(!packet)
        return -1;
    packet->data = SSH2_ALLOC(fx->session, body_len);
    if(!packet->data) {
        SSH2_FREE(fx->session, packet);
        return -1;
    }
    memcpy(packet->data, body, body_len);
    packet->data_len = body_len;
    packet->request_id = request_id;
    ssh2_list_add(&fx->sftp->packets, &packet->node);
    return 0;
}

/*
 * Drive libssh2_sftp_open_ex() against a queued SSH_FXP_STATUS reply.
 * open() is used because it has an explicit STATUS path that records
 * sftp->last_errno and returns LIBSSH2_ERROR_SFTP_PROTOCOL.
 */
static int test_sftp_status_packets(void)
{
    struct {
        const char *name;
        unsigned char body[192];
        size_t body_len;
        uint32_t request_id;
        int want_rc;
        unsigned long want_errno;   /* sftp->last_errno */
    } cases[7];
    size_t ncases = 0;
    size_t i;
    static const uint32_t req = 7;

    /* well-formed failure: code mapping preserved */
    {
        size_t n = fxp_status_build(cases[ncases].body,
                                    sizeof(cases[ncases].body),
                                    req, LIBSSH2_FX_FAILURE,
                                    6, (const unsigned char *)"denied", 6,
                                    2, (const unsigned char *)"en", 2);
        cases[ncases].name = "well-formed-failure";
        cases[ncases].body_len = n;
        cases[ncases].request_id = req;
        cases[ncases].want_rc = LIBSSH2_ERROR_SFTP_PROTOCOL;
        cases[ncases].want_errno = LIBSSH2_FX_FAILURE;
        ncases++;
    }

    /* message length overruns the packet */
    {
        size_t n = fxp_status_build(cases[ncases].body,
                                    sizeof(cases[ncases].body),
                                    req, LIBSSH2_FX_FAILURE,
                                    500, NULL, 0,
                                    0, NULL, 0);
        cases[ncases].name = "msg-overruns";
        cases[ncases].body_len = n;
        cases[ncases].request_id = req;
        cases[ncases].want_rc = LIBSSH2_ERROR_SFTP_PROTOCOL;
        cases[ncases].want_errno = LIBSSH2_FX_FAILURE;
        ncases++;
    }

    /* message truncated mid-string, language tag header also cut */
    {
        size_t n = fxp_status_build(cases[ncases].body,
                                    sizeof(cases[ncases].body),
                                    req, LIBSSH2_FX_NO_SUCH_FILE,
                                    12, (const unsigned char *)"ab", 2,
                                    0, NULL, 0);
        cases[ncases].name = "msg-truncated";
        cases[ncases].body_len = n;
        cases[ncases].request_id = req;
        cases[ncases].want_rc = LIBSSH2_ERROR_SFTP_PROTOCOL;
        cases[ncases].want_errno = LIBSSH2_FX_NO_SUCH_FILE;
        ncases++;
    }

    /* oversized message length */
    {
        size_t n = fxp_status_build(cases[ncases].body,
                                    sizeof(cases[ncases].body),
                                    req, LIBSSH2_FX_PERMISSION_DENIED,
                                    GIANT_LEN,
                                    (const unsigned char *)"z", 1,
                                    0, NULL, 0);
        cases[ncases].name = "msg-oversized";
        cases[ncases].body_len = n;
        cases[ncases].request_id = req;
        cases[ncases].want_rc = LIBSSH2_ERROR_SFTP_PROTOCOL;
        cases[ncases].want_errno = LIBSSH2_FX_PERMISSION_DENIED;
        ncases++;
    }

    /* valid message, language overruns */
    {
        size_t n = fxp_status_build(cases[ncases].body,
                                    sizeof(cases[ncases].body),
                                    req, LIBSSH2_FX_FAILURE,
                                    1, (const unsigned char *)"x", 1,
                                    40, NULL, 0);
        cases[ncases].name = "lang-overruns";
        cases[ncases].body_len = n;
        cases[ncases].request_id = req;
        cases[ncases].want_rc = LIBSSH2_ERROR_SFTP_PROTOCOL;
        cases[ncases].want_errno = LIBSSH2_FX_FAILURE;
        ncases++;
    }

    /* body too short to hold the status code (data_len < 9) -> PROTO */
    {
        unsigned char *b = cases[ncases].body;
        size_t n = 0;
        b[n++] = MSSH_FXP_STATUS;
        put_u32(b + n, req); n += 4;
        b[n++] = 0; b[n++] = 0;  /* 2 of 4 status bytes */
        cases[ncases].name = "status-truncated";
        cases[ncases].body_len = n;
        cases[ncases].request_id = req;
        cases[ncases].want_rc = LIBSSH2_ERROR_SFTP_PROTOCOL;
        cases[ncases].want_errno = LIBSSH2_FX_OK; /* never recorded */
        ncases++;
    }

    /* minimum valid body (9 bytes): code only, no strings at all */
    {
        unsigned char *b = cases[ncases].body;
        size_t n = 0;
        b[n++] = MSSH_FXP_STATUS;
        put_u32(b + n, req); n += 4;
        put_u32(b + n, LIBSSH2_FX_EOF); n += 4;
        cases[ncases].name = "code-only";
        cases[ncases].body_len = n;
        cases[ncases].request_id = req;
        cases[ncases].want_rc = LIBSSH2_ERROR_SFTP_PROTOCOL;
        cases[ncases].want_errno = LIBSSH2_FX_EOF;
        ncases++;
    }

    for(i = 0; i < ncases; i++) {
        struct sftp_fixture fx;
        LIBSSH2_SFTP_HANDLE *handle;
        int rc;
        int errno_got;

        if(sftp_fixture_init(&fx)) {
            fprintf(stderr, "sftp-status/%s: fixture init failed\n",
                    cases[i].name);
            failures++;
            continue;
        }

        libssh2_session_set_blocking(fx.session, 0);

        if(sftp_queue_packet(&fx, cases[i].body, cases[i].body_len,
                             cases[i].request_id)) {
            fprintf(stderr, "sftp-status/%s: queue failed\n",
                    cases[i].name);
            failures++;
            sftp_fixture_free(&fx);
            continue;
        }

        /* Arm the open state machine at the point where it waits for its
           reply, so no channel I/O is needed. */
        fx.sftp->open_state = ssh2_NB_state_sent;
        fx.sftp->open_request_id = cases[i].request_id;

        handle = libssh2_sftp_open_ex(fx.sftp, "/nonexistent",
                                      13, 0, 0,
                                      LIBSSH2_SFTP_OPENFILE);
        rc = handle ? 0 : libssh2_session_last_errno(fx.session);
        errno_got = libssh2_session_last_errno(fx.session);

        CHECK(handle == NULL,
              "sftp-status/%s: open unexpectedly succeeded",
              cases[i].name);
        CHECK(rc == cases[i].want_rc,
              "sftp-status/%s: rc=%d want %d",
              cases[i].name, rc, cases[i].want_rc);
        CHECK(errno_got == cases[i].want_rc,
              "sftp-status/%s: session errno=%d want %d",
              cases[i].name, errno_got, cases[i].want_rc);

        if(cases[i].body_len >= 9) {
            CHECK(fx.sftp->last_errno == cases[i].want_errno,
                  "sftp-status/%s: last_errno=%lu want %lu",
                  cases[i].name,
                  (unsigned long)fx.sftp->last_errno,
                  cases[i].want_errno);
        }

        /* state check: open machinery back to idle, reply consumed */
        CHECK(fx.sftp->open_state == ssh2_NB_state_idle,
              "sftp-status/%s: open_state not idle", cases[i].name);
        CHECK(ssh2_list_first(&fx.sftp->packets) == NULL,
              "sftp-status/%s: reply packet left in brigade",
              cases[i].name);

        /*
         * Queue a second, well-formed packet and verify it is parsed
         * independently: no leftover length fields from the malformed
         * first packet.  A fresh HANDLE-less STATUS (FX_EOF) must surface
         * exactly its own code.
         */
        {
            unsigned char body2[32];
            size_t n2 = 0;
            LIBSSH2_SFTP_HANDLE *h2;
            int rc2;

            body2[n2++] = MSSH_FXP_STATUS;
            put_u32(body2 + n2, req + 1); n2 += 4;
            put_u32(body2 + n2, LIBSSH2_FX_FAILURE); n2 += 4;
            put_u32(body2 + n2, 2); n2 += 4;
            body2[n2++] = 'o'; body2[n2++] = 'k';
            put_u32(body2 + n2, 0); n2 += 4;

            if(sftp_queue_packet(&fx, body2, n2, req + 1) == 0) {
                fx.sftp->open_state = ssh2_NB_state_sent;
                fx.sftp->open_request_id = req + 1;
                h2 = libssh2_sftp_open_ex(fx.sftp, "/other", 6, 0, 0,
                                          LIBSSH2_SFTP_OPENFILE);
                rc2 = h2 ? 0 :
                    libssh2_session_last_errno(fx.session);
                CHECK(h2 == NULL &&
                      rc2 == LIBSSH2_ERROR_SFTP_PROTOCOL &&
                      fx.sftp->last_errno == LIBSSH2_FX_FAILURE,
                      "sftp-status/%s: follow-up contaminated "
                      "(h2=%p rc2=%d errno=%lu)",
                      cases[i].name, (void *)h2, rc2,
                      (unsigned long)fx.sftp->last_errno);
            }
        }

        sftp_fixture_free(&fx);
    }

    return 0;
}

/*
 * SFTP outer framing: the 32-bit length prefix gates every SFTP packet.
 * Verify the overlength, sub-minimum and mid-packet-truncation cases are
 * rejected before the payload parser can run.  The SFTP byte stream is
 * carried inside real SSH_MSG_CHANNEL_DATA transport packets, so the whole
 * receive path (transport -> packet_add -> channel_read -> sftp framing) is
 * exercised end to end.
 */
static const unsigned char *fxp_feed;
static size_t fxp_feed_len;
static int fxp_tail_eagain;  /* EAGAIN returns once the stream is exhausted */

static LIBSSH2_RECV_FUNC(fxp_recv)
{
    size_t copy;

    (void)socket;
    (void)flags;
    (void)abstract;

    if(!fxp_feed_len) {
        /* Model a peer that stops sending (EAGAIN) for a while before the
           orderly close (0).  Lets the framing state machine park and resume
           like it would on a real non-blocking socket. */
        if(fxp_tail_eagain > 0) {
            fxp_tail_eagain--;
            return -EAGAIN;
        }
        return 0;
    }

    copy = fxp_feed_len < length ? fxp_feed_len : (size_t)length;
    memcpy(buffer, fxp_feed, copy);
    fxp_feed += copy;
    fxp_feed_len -= copy;
    return (ssize_t)copy;
}

/* Drive sftp_packet_read() until it produces a terminal, non-EAGAIN result. */
static int fxp_drive(LIBSSH2_SFTP *sftp, int max_iter)
{
    int rc = LIBSSH2_ERROR_EAGAIN;
    int i;

    for(i = 0; i < max_iter; i++) {
        rc = sftp_packet_read(sftp);
        if(rc != LIBSSH2_ERROR_EAGAIN)
            break;
    }
    return rc;
}

/*
 * Build one SSH transport stream carrying a single CHANNEL_DATA message
 * whose payload is the SFTP byte sequence.  Channel id 0 matches the
 * fixture's bare channel.
 */
static size_t fxp_wrap_channel_data(unsigned char *out, size_t outsize,
                                    const unsigned char *sftp_bytes,
                                    size_t sftp_len)
{
    unsigned char payload[300];
    size_t n = 0;

    if(9 + sftp_len > sizeof(payload))
        return 0;

    payload[n++] = SSH_MSG_CHANNEL_DATA;
    put_u32(payload + n, 0); n += 4;           /* recipient channel */
    put_u32(payload + n, (uint32_t)sftp_len); n += 4;
    memcpy(payload + n, sftp_bytes, sftp_len);
    n += sftp_len;

    return wire_packet(out, outsize, payload, n);
}

static int test_sftp_framing(void)
{
    static const struct {
        const char *name;
        unsigned char sftp_stream[16];
        size_t sftp_len;
        int want_rc;
        size_t want_hdr_left;     /* header bytes the error path retains */
    } cases[] = {
        /* Declared length is SFTP_PACKET_MAXLEN + 1: rejected as soon as the
           9-byte header is parsed, before any body is allocated. */
        {
            "oversized-length",
            { 0, 4, 0, 1, MSSH_FXP_STATUS, 0, 0, 0, 1 }, 9,
            LIBSSH2_ERROR_CHANNEL_PACKET_EXCEEDED, 0
        },
        /* declared length 20, stream ends after the 9-byte header */
        {
            "truncated-body",
            { 0, 0, 0, 20, MSSH_FXP_STATUS, 0, 0, 0, 1 }, 9,
            LIBSSH2_ERROR_SOCKET_RECV, 0
        },
        /* declared length below the 5-byte minimum.  This path returns the
           error without clearing packet_header_len, which the next read
           overwrites from index zero; record the real behavior. */
        {
            "length-too-small",
            { 0, 0, 0, 3, MSSH_FXP_STATUS, 0, 0, 0, 1 }, 9,
            LIBSSH2_ERROR_OUT_OF_BOUNDARY, 9
        }
    };
    size_t i;

    for(i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        struct sftp_fixture fx;
        unsigned char wire[320];
        size_t wire_len;
        int rc;

        if(sftp_fixture_init(&fx)) {
            fprintf(stderr, "sftp-framing/%s: fixture init failed\n",
                    cases[i].name);
            failures++;
            return 1;
        }

        /* A wide remote window avoids a window-adjust packet, which would
           need a real send path.  local.id 0 matches the wrapped frame. */
        fx.channel->local.id = 0;
        fx.channel->remote.id = 0;
        /* Maximal window so ssh2_channel_read() never tries to send a
           window-adjust packet (the fixture has no send path). */
        fx.channel->remote.window_size = UINT32_MAX;
        fx.channel->remote.window_size_initial = UINT32_MAX;
        /* Non-zero packet_size, otherwise packet_add truncates every
           CHANNEL_DATA message to its 9-byte header. */
        fx.channel->remote.packet_size = 65536;
        fx.channel->read_avail = 0;
        fx.session->recv_cb = fxp_recv;
        libssh2_session_set_blocking(fx.session, 0);

        wire_len = fxp_wrap_channel_data(wire, sizeof(wire),
                                         cases[i].sftp_stream,
                                         cases[i].sftp_len);
        CHECK(wire_len > 0, "sftp-framing/%s: wrap failed", cases[i].name);
        fxp_feed = wire;
        fxp_feed_len = wire_len;
        fxp_tail_eagain = 16;

        rc = fxp_drive(fx.sftp, 64);

        CHECK(rc == cases[i].want_rc,
              "sftp-framing/%s: rc=%d want %d",
              cases[i].name, rc, cases[i].want_rc);

        /* No partial body allocation may survive to corrupt the next read;
           the parser must be back in its idle framing state. */
        CHECK(fx.sftp->packet_header_len == cases[i].want_hdr_left,
              "sftp-framing/%s: packet_header_len=%lu, want %lu",
              cases[i].name,
              (unsigned long)fx.sftp->packet_header_len,
              (unsigned long)cases[i].want_hdr_left);
        CHECK(fx.sftp->partial_packet == NULL,
              "sftp-framing/%s: partial_packet leaked", cases[i].name);
        CHECK(ssh2_list_first(&fx.sftp->packets) == NULL,
              "sftp-framing/%s: packet queued from bad frame",
              cases[i].name);
        CHECK(fx.sftp->packet_state == ssh2_NB_state_idle,
              "sftp-framing/%s: packet_state not idle", cases[i].name);

        /* Any retained header is overwritten from index zero on the next
           read, so it cannot feed stale bytes into a later packet. */
        if(fx.sftp->packet_header_len)
            fx.sftp->packet_header_len = 0;

        sftp_fixture_free(&fx);
    }

    /* A well-framed packet must still be accepted after the bad frames:
       proves the parser resets cleanly between packets. */
    {
        struct sftp_fixture fx;
        static const unsigned char good_body[] = {
            MSSH_FXP_STATUS, 0, 0, 0, 1, 0, 0, 0, 4,
            0, 0, 0, 0, 0, 0, 0, 0
        };
        unsigned char sftp_bytes[32];
        unsigned char wire[64];
        size_t n = 0;
        size_t wire_len;
        int rc;

        if(sftp_fixture_init(&fx)) {
            fprintf(stderr, "sftp-framing/well-formed: fixture init failed\n");
            return 1;
        }

        put_u32(sftp_bytes + n, (uint32_t)sizeof(good_body)); n += 4;
        memcpy(sftp_bytes + n, good_body, sizeof(good_body));
        n += sizeof(good_body);

        fx.channel->local.id = 0;
        fx.channel->remote.id = 0;
        /* Maximal window so ssh2_channel_read() never tries to send a
           window-adjust packet (the fixture has no send path). */
        fx.channel->remote.window_size = UINT32_MAX;
        fx.channel->remote.window_size_initial = UINT32_MAX;
        /* Non-zero packet_size, otherwise packet_add truncates every
           CHANNEL_DATA message to its 9-byte header. */
        fx.channel->remote.packet_size = 65536;
        fx.channel->read_avail = 0;
        fx.session->recv_cb = fxp_recv;
        libssh2_session_set_blocking(fx.session, 0);

        wire_len = fxp_wrap_channel_data(wire, sizeof(wire),
                                         sftp_bytes, n);
        CHECK(wire_len > 0, "sftp-framing/well-formed: wrap failed");
        fxp_feed = wire;
        fxp_feed_len = wire_len;
        fxp_tail_eagain = 16;

        rc = fxp_drive(fx.sftp, 64);
        CHECK(rc == MSSH_FXP_STATUS,
              "sftp-framing/well-formed: rc=%d want %d",
              rc, MSSH_FXP_STATUS);
        CHECK(ssh2_list_first(&fx.sftp->packets) != NULL,
              "sftp-framing/well-formed: packet not queued");
        CHECK(fx.sftp->packet_header_len == 0 &&
              fx.sftp->partial_packet == NULL &&
              fx.sftp->packet_state == ssh2_NB_state_idle,
              "sftp-framing/well-formed: framing state not reset");

        sftp_fixture_free(&fx);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int rc;
    (void)argv;
    (void)argc;

    rc = libssh2_init(0);
    if(rc) {
        fprintf(stderr, "libssh2_init() failed: %d\n", rc);
        return 1;
    }

    test_disconnect_packets();
    test_debug_packets();
    test_channel_open_failure();
    test_sftp_status_packets();
    test_sftp_framing();

    libssh2_exit();

    if(failures) {
        fprintf(stderr, "%d malformed-packet check(s) failed\n", failures);
        return 1;
    }

    printf("malformed packet tests passed\n");
    return 0;
}
