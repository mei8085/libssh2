# SSH 通道本地关闭与对端关闭交错时迟到报文的处置

本文基于仓库当前 HEAD（`e75fa9a`，libssh2 1.11.2_DEV）的实际代码与一组本地伪造
服务端实验，分析以下问题：

> 本地关闭通道与对端关闭交错时，迟到的 **CHANNEL_DATA / EXTENDED_DATA /
> WINDOW_ADJUST / CHANNEL_REQUEST / CHANNEL_SUCCESS / CHANNEL_FAILURE** 仍携带
> 已关闭（甚至已释放、编号已被复用）的通道号，libssh2 如何定位、复用、释放该号，
> 以及释放后到达的这些报文会被怎么处理。

结论先行：

1. 通道号（`local.id`）由 `ssh2_channel_nextid()` 分配并按“活跃通道的最大编号”
   递增，**永不回收**；`free` 之后该编号不留任何“墓碑”（tombstone）记录，
   `ssh2_channel_locate()` 只按 `local.id` 在当前通道链表与 listener 队列中查找。
2. 因此存在一个真实的**迟到报文串入新通道**窗口：当编号被复用（计数器回绕，
   或调用方/上层重试使 `next_channel` 回到旧值）时，旧通道的 DATA/EXTENDED_DATA/
   WINDOW_ADJUST/exit-status 会被当成新通道的数据和状态处理。
3. `free` 只清理 `SSH_MSG_CHANNEL_DATA` 与 `SSH_MSG_CHANNEL_EXTENDED_DATA` 两种
   排队报文，**SUCCESS/FAILURE 会永久留在 brigade 里**；它们按“类型 + 通道号”
   匹配，会被同一编号上后发出的任意 `want_reply` 请求消费，包括与新通道无关的
   旧应答，以及同一通道上的非预期应答。
4. 请求的应答通道号存在**号空间混用**：libssh2 用本端 `local.id` 回送
   `CHANNEL_SUCCESS/FAILURE`（`packet.c:1188-1194`），而对端期望的是它自己
   分配、并在 OPEN 时告知本端的发送方编号（即本端 `remote.id`）。实验中当
   两端编号不一致时，对端把这条应答判为“请求了未知通道”
   （paramiko 日志 `Channel request for unknown channel 0`），并且该应答随后
   被本端当成另一条通道上的应答消费。
5. 存在真实的**释放后使用（UAF）/悬挂指针**风险：
   - `struct transportpacket.odata/olen/osent` 可以指向上层（通道）缓冲区；
     `free` 之后 `odata` 不失效，`transport_send_existing()` 只比较
     “指针 + 长度”就接受它（`transport.c:936-943`），把**新发起的、恰好同地址
     同长度**的报错误认为旧报文的续发；若指针再也不会以同值出现，则整个异步
     发送路径被**永久卡死**（`olen` 永不清零，之后任何 `send` 都返回 EAGAIN）。
   - 忽略型扩展数据路径把 `session->packet.payload`、
     `readPack_state == jump1`、`fullpacket_state == created` 留在会话上；
     `free` 只清 `packAdd_channelp`/`packAdd_state`，不观察传输层状态，
     导致这份**属于已释放通道的旧载荷**在下一次读时被当作一条全新报文
     完整重解析，并以“当前占用该编号的通道”归属（`packet.c` 走 idle 路径，
     而非 `jump_point1`）。
6. `libssh2_channel_close()` 在**尚未看到对端 CLOSE** 时即可返回 0：
   `channel.c:2503-2521` 的等待循环把“读到任意非 EAGAIN 结果”都当成可以
   结束等待，于是对端先回 EOF（或任何别的报文）都会让 `close()` 返回 0，
   而 `remote.close` 仍为 0。之后 `free` 释放通道，对端按 RFC 4254 §5.3
   必须回送的 CLOSE 迟到，命中被复用编号的新通道，把**活动通道**直接标记为
   `remote.close = remote.eof = 1`，造成提前 EOF/读 0。

---

## 1. 相关代码定位

### 1.1 通道号的分配与查找

`src/channel.c:51-73`：

```c
uint32_t ssh2_channel_nextid(LIBSSH2_SESSION *session)
{
    uint32_t id = session->next_channel;
    LIBSSH2_CHANNEL *channel = ssh2_list_first(&session->channels);
    while(channel) {
        if(channel->local.id > id)
            id = channel->local.id;
        channel = ssh2_list_next(&channel->node);
    }
    /* This is a shortcut to avoid waiting for close packets on channels we
     * have forgotten about, This *could* be a problem if we request and close
     * 4 billion or so channels in too rapid succession for the remote end to
     * respond, but the worst case scenario is that some data meant for
     * another channel gets picked up by the new one.... Pretty unlikely all
     * told...
     */
    session->next_channel = id + 1;
    ...
    return id;
}
```

注释本身已经承认了“另一条通道的数据可能被新通道收下”的后果，但代码没有做
任何防护。**注意它取的是活跃通道的 `max(local.id)`，并且 `id + 1` 会 32 位回绕**：
回绕后 `next_channel` 变成 0，下一次分配又取 `max(live)`，于是可能直接发出一个
**已在使用中的编号**（见 §3.7 实验 R7）。

`src/channel.c:79-105` 的查找只遍历 `session->channels` 和各个 listener 的
`queue`，命中条件只有 `channel->local.id == channel_id`：

```c
for(channel = ssh2_list_first(&session->channels); channel;
    channel = ssh2_list_next(&channel->node)) {
    if(channel->local.id == channel_id)
        return channel;
}
...
```

**没有“这个编号曾经属于一个已关闭/已释放通道”的历史记录**，因此无法区分
“迟到的旧报文”与“新通道的合法报文”。

### 1.2 通道号的复用时点

- 主动打开：`channel.c:133` 在状态机 `idle` 分支就调用
  `ssh2_channel_nextid()`，并在 `channel.c:167` 立刻把尚未收到
  OPEN_CONFIRMATION 的**预备通道**挂进 `session->channels`。
- 被动接受（forwarded-tcpip / x11 / auth-agent）：`packet.c:177/372/532` 在
  发送 OPEN_CONFIRMATION 之前就分配 `local.id`。

这两点意味着：**“编号已占用”和“编号对应的通道已经可用”不是同一时刻**。
在 `open()` 的 EAGAIN 续跑期间，预备通道已经可被 `ssh2_channel_locate()` 找到
（本仓实验 §3.4 的 “during-open” 列即由此产生）。

### 1.3 释放

`src/channel.c:2600-2702`（`ssh2_channel_free`）：

```c
/* Clear out packets meant for this channel */
ssh2_htonu32(channel_id, channel->local.id);
while(ssh2_packet_ask(session, SSH_MSG_CHANNEL_DATA, &data,
                      &data_len, 1, channel_id, 4) >= 0 ||
      ssh2_packet_ask(session, SSH_MSG_CHANNEL_EXTENDED_DATA, &data,
                      &data_len, 1, channel_id, 4) >= 0)
    SSH2_FREE(session, data);
```

只清 DATA 与 EXTENDED_DATA。**`SUCCESS`/`FAILURE` 不清**（§3.5）。随后：

```c
if(session->packAdd_channelp == channel) {
    session->packAdd_channelp = NULL;
    session->packAdd_state = ssh2_NB_state_idle;
}
```

清掉 packet_add 的“保管指针”，但**不清传输层的 `readPack_state` /
`fullpacket_state` / `session->packet.payload`**（§3.6）。

### 1.4 迟到报文的分发

`src/packet.c:618` 起的 `ssh2_packet_add()` 按消息类型分派：

| 报文 | 代码位置 | 找不到通道时的行为 |
|---|---|---|
| `CHANNEL_DATA` / `CHANNEL_EXTENDED_DATA` | `packet.c:924-952` | `ssh2_err(CHANNEL_UNKNOWN)` 后丢弃，但仍设置会话级 `err_code` |
| `CHANNEL_EOF` | `packet.c:1062-1078` | 静默忽略 |
| `CHANNEL_WINDOW_ADJUST` | `packet.c:1297-1324` | 静默忽略 |
| `CHANNEL_CLOSE` | `packet.c:1211-1229` | 静默忽略 |
| `CHANNEL_REQUEST` (含 exit-status / exit-signal) | `packet.c:1087-1205` | 仅 `exit-status`/`exit-signal` 会 `locate`；`want_reply` 分支（`packet.c:1188`）**无条件**回 FAILURE，且回抄的是报文里的 recipient channel |
| `CHANNEL_SUCCESS` / `CHANNEL_FAILURE` | `packet.c:1387` 兜底入 brigade | 作为普通报文入队，等待后续 `ssh2_packet_ask()` 按“类型 + 通道号”匹配 |

关键片段：

```c
/* packet.c:940-949 */
if(!channelp) {
    ssh2_err(session, LIBSSH2_ERROR_CHANNEL_UNKNOWN,
             "Packet received for unknown channel");
    SSH2_FREE(session, data);
    session->packAdd_state = ssh2_NB_state_idle;
    return 0;                    /* 返回值 0，但 err_code 已污染 */
}
```

`CHANNEL_CLOSE` 分支（`packet.c:1211`）与 `CHANNEL_EOF` 分支都把
`remote.close/eof` 直接写在**按编号查到的通道**上，没有校验该报文是否属于
当前这次通道生命周期。

### 1.5 请求应答的通道号（号空间混用）

`packet.c:1188-1195`：

```c
if(want_reply) {
    unsigned char packet[5];
ssh2_packet_add_jump_point4:
    session->packAdd_state = ssh2_NB_state_jump4;
    packet[0] = SSH_MSG_CHANNEL_FAILURE;
    memcpy(&packet[1], data + 1, 4);      /* 原样回抄“recipient channel” */
    rc = ssh2_transport_send(session, packet, 5, NULL, 0);
    ...
}
```

这里的 `data + 1` 是**对端发来的 recipient channel**，即本端的 `local.id`；
而对端在收到应答时会用它自己的发送方编号去匹配。libssh2 把本端编号当成了对端
编号回送，属于号空间混用。仓库中所有请求类操作（`channel.c:884` 的 setenv、
`channel.c:1004` 的 pty、`channel.c:1369` 的 x11、`channel.c:1487` 的 process
startup）都是拿 `local.id` 去匹配回包：

```c
ssh2_htonu32(channel->setenv_local_channel, channel->local.id);   /* setenv */
...
rc = ssh2_packet_requirev(session, reply_codes, &data, &data_len,
                          1, channel->setenv_local_channel, 4, ...
```

实验（`s04b.py` / `s20_reply_misdirect.py`）：把服务端编号计数器设成 1234 后
打开通道，本端 `local.id=0`、`remote.id=1234`。服务端向本端编号 0 发一条
`want_reply=1` 的未知请求，libssh2 回送 `CHANNEL_FAILURE`：

```
OPENED idx=0 local=0 remote=1234
  SRV Channel request for unknown channel 0        <-- 对端判为未知通道
```

`ssh2_packet_add()` 回抄的是 `data + 1`（本端 `local.id`），服务端拿它去匹配
自己的 `chanid`（1234），因此永远匹配不上。

反过来，若两条通道的编号互相错开（`s20`：A 是 `local=0/remote=5`，
B 是 `local=1/remote=0`），服务端向**本端编号 0**（即 A）发请求时，
本端回送的 FAILURE 带的是 `chan=0`；服务端把它匹配到自己的通道 0（即 B），
于是 B 被关闭，而真正被请求的 A 毫无影响：

```
OPENED idx=0 local=0 remote=5
OPENED idx=1 local=1 remote=0
  A (server 5) closed? False   B (server 0) closed? True
  CH 1 ... local=1 remote=0 ... rclose=1 reof=1
```

### 1.6 传输层的异步发送与“指针+长度”校验

`src/libssh2_priv.h:642-646`：

```c
ssize_t ototal_num;         /* size of outbuf in number of bytes */
const unsigned char *odata; /* original pointer to the data */
size_t olen;                /* original size of the data we stored in outbuf */
size_t osent;               /* number of bytes already sent */
```

`src/transport.c:922-946`：

```c
static int transport_send_existing(LIBSSH2_SESSION *session,
                                   const unsigned char *data,
                                   size_t data_len, ssize_t *ret)
{
    ...
    if(!p->olen) { *ret = 0; return LIBSSH2_ERROR_NONE; }

    /* send as much as possible of the existing packet */
    if(data != p->odata || data_len != p->olen) {
        ssh2_deb((session, LIBSSH2_TRACE_SOCKET,
                  "Address is different, returning EAGAIN"));
        return LIBSSH2_ERROR_EAGAIN;
    }
    ...
    rc = SSH2_SEND(session, &p->outbuf[p->osent], length, ...);
```

`odata` 被当作调用者的“身份令牌”：只要指针与长度都相同，就认为这是同一个
待发送报文并继续发送 `outbuf` 中已加密的剩余字节。这个检查**不验证指针是否
仍然有效**，也不验证其内容是否仍是当初那份数据。

通道结构里有两个直接传给 `ssh2_transport_send()` 的定长缓冲：

- `channel->write_packet[13]`（`libssh2_priv.h:532`，DATA 头）
- `channel->reqPTY_packet[41+256]`（`libssh2_priv.h:496`，window-change 定长 39）

`channel->adjust_adjust[9]`（`libssh2_priv.h:522`）则通过
`ssh2_channel_receive_window_adjust()`（`channel.c:1738`）直接发送。

---

## 2. 交错时序与代码路径

下面把“本地关闭”与“对端关闭”的两种合法交错，以及迟到报文的插入点列出。

### 2.1 时序 A：对端先关（peer-initiated close）

```
peer:  EOF ─► CLOSE
lib:   packet_add CLOSE  -> remote.close = remote.eof = 1  (packet.c:1211-1226)
app:   libssh2_channel_close()  -> local.close = 1, close_cb
app:   libssh2_channel_free()   -> 清 DATA/EXT，摘链，释放结构
peer:  （不应再发）迟到的 DATA / WIN / REQ / SUCCESS
lib:   locate(local.id) 失败 -> DATA 丢弃但污染 err_code；其余静默丢弃
       若编号已被复用 -> 迟到报文归属新通道
```

### 2.2 时序 B：本地先关（local-initiated close）

```
app:   libssh2_channel_close()
lib:   channel_send_eof (channel.c:2319)
       channel->close_packet[0..4] = CLOSE, remote.id  (channel.c:2481-2483)
       ssh2_transport_send(close_packet)             (channel.c:2488)
       while(!remote.close && !rc && socket connected)
           rc = ssh2_transport_read(session);        (channel.c:2505-2506)
app:   libssh2_channel_free()  -> 释放结构，通道号成为“空洞”
peer:  按 RFC 4254 §5.3 必须回送 CLOSE（以及可能的尾部 DATA）
lib:   若在等待循环中被读到 -> 正常；否则报文留在 socket
       若编号已复用 -> 对端“应答 CLOSE”变成新通道的关闭
```

`channel.c:2503-2521`：

```c
if(channel->close_state == ssh2_NB_state_sent) {
    /* We must wait for the remote SSH_MSG_CHANNEL_CLOSE message */
    while(!channel->remote.close && !rc &&
          (session->socket_state != SSH2_SOCKET_DISCONNECTED))
        rc = ssh2_transport_read(session);
}

if(rc != LIBSSH2_ERROR_EAGAIN) {
    channel->local.close = 1;
    if(channel->close_cb)
        SSH2_CHANNEL_CLOSE(session, channel);
    channel->close_state = ssh2_NB_state_idle;
}
return rc >= 0 ? 0 : rc;
```

这个循环只有在“收到 `remote.close`”或“返回 EAGAIN”或“socket 断开”时才停止。
`ssh2_transport_read()` 返回的是**刚刚处理掉的报文类型**（正数）或 0/EAGAIN/
负错误。循环条件里的 `!rc` 只挡住 0，对正数类型值没有约束：只要读到的第一条
报文不是对端 CLOSE（例如对端先发 EOF），`rc` 就是 96 之类正数，`!rc` 为假，
循环退出；随后 `rc != EAGAIN` 成立，`local.close` 被置 1，函数返回 `0`——
**此时 `remote.close` 仍为 0**。

用诊断副本（`/tmp/ssh-late-796/diag`）在真实 socket 上抓到的循环轨迹：

```
--- close with peer completely silent ---
DIAGCLOSE iter=0 rc=-37 remote.close=0   <-- 首次进入：没有数据，EAGAIN
DIAGCLOSE exit rc=-37 remote.close=0
DIAGCLOSE iter=0 rc=96  remote.close=0   <-- BLOCK_ADJUST 重试后读到 EOF(96)
DIAGCLOSE exit rc=96    remote.close=0
CLOSE rc=0                                <-- 返回 0，但 remote.close 仍是 0
```

（这里“peer completely silent”指对端在收到本端 CLOSE 之前没有主动发任何
报文；它标识出的那条 96 是 harness 侧在关闭过程中产生的 EOF。
只要第一条到达的报文不是 CLOSE，结果就相同——`s55` 用 EOF / WINDOW_ADJUST /
DATA 三种前置报文各复现了一次，均得到 `CLOSE rc=0` 且 `rclose=0`。）

也就是说：`LIBSSH2_CHANNEL_CLOSE` 的“等待对端关闭”只在**对端恰好回 CLOSE**
时成立；只要对端先发了 EOF（或任何别的报文），`close()` 就会“提前成功”，
把通道交给 `free()` 去释放，而**对端随后必然回送的 CLOSE 还留在 socket 里**。
实验 §3.9 及 §3.4 的 S2 行展示了这条迟到 CLOSE 如何命中复用编号的新通道。

### 2.3 迟到报文的插入点

| 插入点 | 后果 |
|---|---|
| `free` 之前、通道仍在链表 | 迟到报文归属旧通道：数据仍会被 `read` 读出，`CLOSE`/`EOF` 会置位 `remote.*`；对已发出的请求，迟到的 `SUCCESS/FAILURE` 仍可能满足它 |
| `free` 之后、编号未复用 | DATA/EXT 被丢弃并污染会话 `err_code`（`-23`）；EOF/WIN/CLOSE 静默丢弃；SUCCESS/FAILURE 入 brigade 常驻 |
| `free` 之后、编号复用中（`open()` 预备通道已入链） | DATA/EXT 会立刻写入**尚未确认**的新通道，`read_avail` 增长 |
| 编号已正式复用 | 全部按新通道处理：数据串入、窗口膨胀、exit-status 污染、CLOSE 提前关闭 |
| `next_channel` 回绕或外部重置 | `ssh2_channel_nextid()` 可直出已占用编号，见 §3.7 |

---

## 3. 本地伪造服务端实验与可观察结果

### 3.1 实验装置

- `libssh2` 以 `Debug` + `ENABLE_DEBUG_LOGGING` 静态构建（`/tmp/ssh-late-796/build`），
  源码即本仓 HEAD，未做任何修改。
- 另建一份带 `fprintf` 诊断的**独立副本**（`/tmp/ssh-late-796/diag`）用于确认
  EAGAIN 续跑点；正式结论均以未修改的库为准。
- 伪造服务端：paramiko 5.1.0（`Transport.start_server`），可**逐条注入**任意
  通道报文（`SSH_MSG_CHANNEL_*`），并能记录服务端真实收发的报文。
- 客户端：`client.c`，直接包含 `libssh2_priv.h`/`transport.h`/`channel.h`
  （与 `tests/test_simple.c` 相同的做法），对外暴露 `dump`（会话/通道/brigade
  全量状态）、`pump`（驱动 `ssh2_transport_read`）、`nonblock`、`sendfail`
  （让下一次 `send()` 返回 `-EAGAIN`）、`sendpart`（只发一半字节）、
  `setnext`（重置 `session->next_channel`，用来**确定性触发编号复用**）、
  `listch`、`extpacket`（直接调用 `ssh2_packet_add` 构造忽略型扩展数据）等。
- 脚本见附录 A；所有结果来自实际执行输出。

> 说明：SSH 传输层加密后，`send` 回调看到的是密文，无法按消息类型注入
> EAGAIN。因此“让某条报文的发送失败”这一步有两种做法：
> (a) `sendfail N` 让接下来的 N 次 `send()` 整体返回 `-EAGAIN`（不区分类型）；
> (b) `extpacket` 直接构造明文 payload 调 `ssh2_packet_add()`，跳过传输层，
>     精确进入忽略型扩展数据 / `jump1` 路径。
> §3.6 的两段证据分别来自 (a)+真实 socket（`s22`、`s53`）和 (b)（`s15`、`s39`）；
> 其余实验全部走真实 socket 与真实报文。

### 3.2 基准：正常关闭、释放与“未知通道”

对端先发 `exit-status(7)`、`xon-xoff`、`EOF`、`CLOSE`，客户端 `close` + `free`
之后，再对同一编号发送全部迟到报文类型：

```
CH 0 ... rclose=1 reof=1 exit=7 exitset=1
EXSTATUS has=1 status=7
CLOSE rc=0
FREE rc=0
STATE afterlate ... err_code=-23 err=Packet received for unknown channel
PKT 1 type=99 chan=0 len=5 head=0
PKT 2 type=100 chan=0 len=5 head=0
PKTCOUNT 2
```

可观察结果：

- DATA/EXT 被丢弃，但**会话级 `err_code` 被写成 `-23`**（`CHANNEL_UNKNOWN`）。
  它不会在 `ssh2_channel_free()` 里被清掉，只有下一次进入
  `ssh2_wait_socket()`（`session.c:565`，即阻塞模式的 API 重新等待 socket）
  才会复位。因此非阻塞用法下，一次完全合法的对端迟到数据会让后续
  `libssh2_session_last_error()` 返回 `CHANNEL_UNKNOWN`，直到下一次阻塞等待。
- `SUCCESS`/`FAILURE` 两种报文**留在了 brigade 里**，`free` 不会清理。
- EOF/WIN/CLOSE 静默丢弃，没有副作用。

### 3.3 序号回绕/强行复用：旧数据串入新通道（真实串扰）

用 `setnext 0` 把 `next_channel` 压回 0，打开新通道（新 `local=0`，
服务端编号为 1），然后向编号 0 注入旧通道的迟到报文：

```
### dump after reopen
CH 1 ... local=0 remote=1 ... read_avail=19 exit=77 exitset=1
PKT 1 type=94 chan=0 len=19 head=9     <-- 旧 DATA
PKT 2 type=95 chan=0 len=22 head=13    <-- 旧 EXTENDED_DATA
PKT 3 type=99 chan=0 len=5 head=0      <-- 旧 SUCCESS
PKT 4 type=100 chan=0 len=5 head=0     <-- 旧 FAILURE

### read B
READ rc=10 data="STALE-DATA"

### pump late-to-reused
CH 1 ... lwin=2220608 read_avail=24
PKT 1 type=95 chan=0 len=22 head=13
PKT 2 type=99 chan=0 len=5 head=0
PKT 3 type=100 chan=0 len=5 head=0
PKT 4 type=94 chan=0 len=24 head=9
### read B again
READ rc=15 data="SEEPED-INTO-NEW"
```

**结论：旧通道的载荷被新通道原样读出**（`STALE-DATA`、`SEEPED-INTO-NEW`），
`WINDOW_ADJUST` 也把新通道的 `local.window_size` 从 `2097152` 抬到 `2220608`
（另一次实验抬到 `3145728`）。这是 RFC 4254 §5.1/§6 意义上不可接受的串道。

### 3.4 时序 × 报文类型矩阵

矩阵对每个组合都执行：打开 A → 两种关闭时序之一 → `free` → `setnext 0` →
打开 B → 在指定阶段注入一条迟到报文 → 观察新通道状态。
S1 = 对端先 CLOSE、客户端 close+free；S2 = 客户端先 CLOSE+free。

```
S1 (peer CLOSE, client close, free)
  late DATA           | read_avail=8, READ rc=8 data="OLD-DATA"
  late EXTENDED       | read_avail=7, READ rc=-9 (timeout / EAGAIN)
  late WINDOW_ADJUST  | local_window=3145728
  late EOF            | remote.eof
  late CLOSE          | remote.close, remote.eof
  late exit-status    | exit_status=42
  late SUCCESS        | clean
  late FAILURE        | clean
  late nothing        | clean

S2 (client CLOSE+free before peer CLOSE)
  late DATA           | read_avail=8, remote.close, READ rc=8 data="OLD-DATA"
  late EXTENDED       | read_avail=7, remote.close, READ rc=0
  late WINDOW_ADJUST  | remote.close, remote.eof, local_window=3145728
  late EOF            | remote.close, remote.eof
  late CLOSE          | remote.close, remote.eof
  late exit-status    | remote.close, remote.eof, exit_status=42
  late SUCCESS/FAILURE| clean（但会留在 brigade）
```

> S2 每一行都带 `remote.close`/`remote.eof`，原因是本端 `close()` 后
> `free()`、再打开 B 时，**对端对 A 的应答 CLOSE/EOF 才到达**（§3.9）。
> 换句话说 S2 的所有行都叠加了“对端合法关闭应答毒化新通道”的效应，
> 不应把它归因于被注入的那条报文。S1 用 `silent_close()` 抑制了对端的
> 自动应答，因此能干净地隔离出“注入报文本身的效应”。

另一个按阶段（复用前 / `open()` 进行中 / 复用后）展开的矩阵（同一装置，
每条迟到报文都注入到**编号已被新通道占用之后**）：

```
late pkt         phase          | 新通道上的可观察结果
DATA             before-open    | no effect            (编号尚未被占用，报文被丢弃)
EXTDATA          before-open    | no effect
WINDOWADJ        before-open    | no effect
EOF              before-open    | no effect
CLOSE            before-open    | no effect
EXITSTATUS       before-open    | no effect
REQ(no-reply)    before-open    | no effect
REQ(want-reply)  before-open    | no effect
SUCCESS          before-open    | brigade+1            (留在队列，等后续请求消费)
FAILURE          before-open    | brigade+1
DATA             during-open    | read_avail=9; brigade+1; READ rc=9 data="LATE-DATA"
EXTDATA          during-open    | read_avail=8; brigade+1（READ 超时，见说明）
WINDOWADJ        during-open    | local.window_size inflated to 3097152
EOF              during-open    | remote.eof=1
CLOSE            during-open    | remote.close=1; remote.eof=1
EXITSTATUS       during-open    | exit_status=99 received
REQ(no-reply)    during-open    | no effect            (只对未知通道回 FAILURE)
REQ(want-reply)  during-open    | no effect
SUCCESS          during-open    | brigade+1
FAILURE          during-open    | brigade+1
DATA             after-open     | read_avail=9; brigade+1; READ rc=9 data="LATE-DATA"
EXTDATA          after-open     | read_avail=8; brigade+1（READ 超时，见说明）
WINDOWADJ        after-open     | local.window_size inflated to 3097152
EOF              after-open     | remote.eof=1
CLOSE            after-open     | remote.close=1; remote.eof=1
EXITSTATUS       after-open     | exit_status=99 received
REQ(no-reply)    after-open     | no effect
REQ(want-reply)  after-open     | no effect
SUCCESS          after-open     | brigade+1
FAILURE          after-open     | brigade+1
```

读法：

- `before-open` 行是“编号空洞期”：DATA/EXT 被丢弃（并写入 `err_code=-23`），
  EOF/WIN/CLOSE 静默丢弃，只有 SUCCESS/FAILURE 会作为普通报文常驻 brigade。
- `during-open` 与 `after-open` 行为相同，因为 `channel.c:167` 在发出 OPEN、
  收到 OPEN_CONFIRMATION 之前就已把预备通道挂进 `session->channels`；
  差异只在于 `during-open` 时通道的 `remote.id`/窗口还没填好。
- 这两个阶段之所以能命中，前提是**编号已被新通道占用**（实验中用 `setnext`
  精确制造）；若编号没有复用，迟到报文只会走 `before-open` 那一列。
- `late EXTENDED` 的 `READ rc=-9` 是测试客户端用 `libssh2_channel_read_ex()`
  读标准流所致：扩展数据默认不进标准流（除非设置了 MERGE/IGNORE），
  因此 `read_avail` 已计入但标准读会等到超时。这不是缺陷，只是读法的副作用；
  `read_avail` 的增长本身已经证明报文被归属到了新通道。
- `REQ(no-reply)` / `REQ(want-reply)` 两行“no effect”是指**新通道状态**没有
  变化；`want_reply` 的请求仍会让 libssh2 回一条 `CHANNEL_FAILURE`（见 §1.4
  与 §5.2 的号空间问题），只是本矩阵没有观测线上报文。

### 3.5 陈旧 SUCCESS/FAILURE 被后续请求消费

实验：A 存活时向编号 0 注入一条**非请求**的 `SUCCESS` 和 `FAILURE`，
`free` A 之后它们仍在 brigade；复用编号 0 打开 B，然后**屏蔽服务端真实的
应答**（`_send_message` 拦截 type 99/100）：

```
### dump a2 (stale replies survive free)
PKT 1 type=99 chan=0 len=5 head=0
PKT 2 type=100 chan=0 len=5 head=0
### open B ... local=0 remote=1
### dump a3
PKT 1 type=99 chan=0 len=5 head=0
PKT 2 type=100 chan=0 len=5 head=0    <-- 两条陈旧应答都还在
### pty B (peer reply suppressed)
NBPTY rc=0 err=0                      <-- 成功，但服务端应答被丢弃
### dump a4
PKT 1 type=100 chan=0 len=5 head=0    <-- 陈旧 SUCCESS 被消耗
### setenv B (peer reply suppressed)
NBSETENV rc=-22                       <-- 由陈旧 FAILURE 判定“被拒绝”
### dump a5
PKTCOUNT 0                            <-- 陈旧 FAILURE 也被消耗
  peer replies dropped on the wire: [(99, 0)]
  peer requests actually seen: [('pty', 1)]
```

**结论：请求的结果完全由不属于它的旧应答决定**——PTY 请求“成功”了，但
服务端根本没收到应答；SETENV 被“拒绝”，而服务端其实答应了。这类攻击/
竞争不需要编号复用也能发生（§3.10 在同一通道上复现）。

### 3.6 忽略型扩展数据：传输层状态与通道释放不同步

`extignore` 模式 + 让窗口调整发送失败（使用真实 socket，报文来自线上，
脚本 `s53_wire_defer.py`）：

```
SENDFAIL 1
pump1 (transport read -> packet_add 走忽略路径 -> adjust 发送 EAGAIN)
STATE d1 ... packAdd=11 readPack=11 fullpacket=2 keepch=0x...7d0 ... pending=.../9
### free A
FREE rc=0
STATE d2 ... packAdd=0  readPack=11 fullpacket=2 keepch=(nil) ... pending=.../9
### sendfail 0
### resume (再次驱动 ssh2_transport_read)
PUMP1 rc=-37
STATE d3 ... err_code=-23 (Packet received for unknown channel)
             readPack=0 fullpacket=0 ... pending=.../9
```

（`err_code=-23` 出现在 **d3**，即旧的、属于 A 的载荷被重新解析时按当前
编号查找失败；`pending=.../9` 在 d1→d3 全程不变，说明那条 9 字节窗口调整
报文一直卡在传输层。）

过程可以精确地还原为：

1. `ssh2_packet_add()` 在 `packet.c:986` 存下 `packAdd_channelp`，在
   `packet.c:992` 调 `ssh2_channel_receive_window_adjust()`；发送返回 EAGAIN 时
   直接从 `packet.c:995` 返回，**保留 `packAdd_state = jump1`，并且不释放
   `data`**。此时 `data` 与 `session->packet.payload` 是同一块内存。
2. `transport_fullpacket()`（`transport.c:356-367`）看到 EAGAIN：
   - `packAdd_state != idle` ⇒ **不清 `p->payload`**；
   - 于是 `ssh2_transport_read()`（`transport.c:896-908`）设
     `readPack_state = jump1` 后返回 EAGAIN；
   - `fullpacket_state` 仍停在 `created`。
   **整个“已解密但未处理完”的报文（含 payload 指针）被原地保留。**
3. `ssh2_channel_free()`（`channel.c:2681`）把 `packAdd_channelp` 置 NULL，
   并把 `packAdd_state` 置 idle，**但完全不触碰** `readPack_state`、
   `fullpacket_state` 和 `session->packet.payload`。
4. 下一次 `ssh2_transport_read()` 因 `readPack_state == jump1`
   直接跳到 `ssh2_transport_read_point1`（`transport.c:452-457`），再进
   `transport_fullpacket()`；因为 `fullpacket_state == created`，它会用**同一份
   payload** 再次调用 `ssh2_packet_add()`。而此时 `packAdd_state` 已被 `free`
   复位成 `idle`，所以走的**不是** `jump_point1` 的续跑分支，而是把这份旧
   payload 当作**一条全新报文从头解析**。

用带 `fprintf` 的独立诊断副本（`/tmp/ssh-late-796/diag`，非仓库源码）可以
直接看到第 4 步：

```
DIAG transport: resuming readPack jump1 fullpacket=2
DIAG fullpacket: calling packet_add payload=0x... len=28 packAdd=0   <-- idle!
```

后果有两个，均已实测：

- **旧载荷被二次解析并按“当前编号”归属**：`s54_deferred_into_provisional.py`
  中把 A 的忽略型扩展数据延迟处理后释放 A、`setnext 0`、以非阻塞方式打开 B
  （B 会被挂入 `session->channels`，见 §1.2），再续跑一次，A 的旧载荷被作为
  新报文重新解析并以 `chan=0` 进入 brigade：
  ```
  ### dump z1
  PKT 1 type=95 chan=0 len=26 head=13
  ```
  该实验里 `open B` 本身返回 `OPENFAIL -37 Would block sending channel-open
  request`，所以 B 仍是预备通道；这正是危险所在——报文归属由
  “当前谁占着这个编号”决定，而不是由“报文属于哪次通道生命周期”决定。
- **发送方向被永久卡死**：`packet.c:995` 的 EAGAIN 返回发生在
  `ssh2_channel_receive_window_adjust()` 内部，后者已经把 9 字节窗口调整
  报文留在 `session->packet`（`olen=9`，`odata = &channel->adjust_adjust`）。
  `free` 之后该指针成为悬挂指针，而 `transport_send_existing()`
  （`transport.c:936-943`）只认“指针 + 长度”，**此后任何新报文都因为指针
  不同而被拒绝**（见 §3.11 的同类现象与 §3.6 实测的 `pending=.../9`）。

> 补充说明：本仓未能复现“`jump_point1` 以 NULL `packAdd_channelp` 续跑”的崩溃。
> 原因是 `channel.c:2681-2684` 总是成对地把 keeper 与 `packAdd_state` 一起复位，
> 而 `packet.c:990` 也总是成对设置；因此 `packAdd_state == jump1` 时 keeper
> 一定非 NULL。真正的缺陷是**复位了 `packAdd_state` 却没有复位传输层状态**，
> 这导致“重复解析 + 跨编号归属”，而不是空指针解引用。

### 3.6b 窗口调整的待发状态

`ssh2_channel_receive_window_adjust()`（`channel.c:1738` 起）在发送失败时
（`channel.c:1775-1787`）：

```c
rc = ssh2_transport_send(channel->session, channel->adjust_adjust, 9, NULL, 0);
if(rc == LIBSSH2_ERROR_EAGAIN) { ... return rc; }
else if(rc) {
    channel->adjust_queue = adjustment;   /* 重新入队，但 send 侧的 pending 仍在 */
    return ssh2_err(..., LIBSSH2_ERROR_SOCKET_SEND, ...);
}
```

下一次对**同一个通道**调用时，`channel->adjust_adjust` 地址不变、长度不变，
`transport_send_existing()` 才会放行并补完。若通道已被释放，这个“同一指针”
永远不会再出现。

### 3.7 编号回绕直接分配重复编号

```
### setnext 0xffffffff
### open A -> OPENED idx=0 local=4294967295 remote=0
### open B -> OPENED idx=1 local=4294967295 remote=1
### listch
LISTCH 0 ptr=0x...7d0 local=4294967295 remote=0
LISTCH 1 ptr=0x...840 local=4294967295 remote=1
```
（另一组：`setnext 0xffffffff` 后 `open A` 得 `local=0xffffffff`，再 `open B`
仍得 `local=0xffffffff`。）

对端随后向该编号发数据：

```
read channel A: READ rc=17 data="FOR-WHICH-CHANNEL"
read channel B: READ rc=-9 (timeout)
```

`ssh2_channel_nextid()` 在 `id` 回绕后 `id + 1 == 0`，但 `id` 又会被
活跃通道的 `max(local.id)` 抬回去，于是**同一个编号被两条活跃通道共享**，
`ssh2_channel_locate()` 永远只返回链表中的第一条。这是 §1.1 注释所担忧
情况的直接实现。

### 3.8 定长缓冲区 + “指针+长度”校验：陈旧字节被当成本次数据

同一个通道上，先让 `window-change`（39 字节，`channel->reqPTY_packet`）
只发出去一部分，再发一次不同宽度的 `window-change`：

```
sendpart 10
nonblock 0
PTYSIZE(111) rc=-37                       <-- 部分发送，pending 保留
PENDING olen=39 osent=10 total=68
PTYSIZE(222) rc=0                         <-- 返回成功
PENDING olen=0 osent=10 total=0
server-side window-change requests received: [('wchange', 0, 111, 24)]
```

即：第二次 `window-change(222)` 返回成功，但**对端收到的是第一次的 111**，
并且 `channel->reqPTY_state` 已经被复位——调用方无从得知本次变更从未生效。
根因是 `ssh2_transport_send()` 先进入 `transport_send_existing()`
（`transport.c:936`），发现 `data == p->odata && data_len == p->olen`（两次都用
同一个定长成员）就当成“继续发上一条”，而不是“发这一条新报文”。

同样的模式适用于 `channel->write_packet[13]` 与 `channel->adjust_adjust[9]`，
以及 `channel->close_packet[5]`。

### 3.9 `close()` 在对端 CLOSE 未到时返回 0

对端按 RFC 4254 §5.3 回送的 CLOSE 落在**新打开的活跃通道**上，直接把 B
标记为远端已关闭/EOF。用 `s66_verify_s43.py` 对**两个方向**分别做了记录
（服务端侧用 `Transport._send_message` 的封装，客户端侧用 libssh2 的状态）：

```
### close A -> rc, while remote.close not yet seen
CLOSE rc=0
### dump right after close
CH 0 ... lclose=1 leof=1 rclose=0 reof=1     <-- 本端已关，对端 CLOSE 未到
### free A -> FREE rc=0
### setnext 0 / open B -> OPENED idx=1 local=0 remote=1   (t=0.041s)
server->client EOF/CLOSE with timestamps (B opened at 0.041):
    (0.041, 'EOF',   0)      <-- 对端对 A 的关闭应答，全部在 B 打开之后到达
    (0.041, 'CLOSE', 0)
### dump B (poisoned by the old channel's answering CLOSE)
CH 1 ... local=0 remote=1 ... rclose=1 reof=1
### eof B -> EOFSTAT 1
### read B -> READ rc=0
```

关键点：这两条报文**不是测试脚本注入的**——`s43` 全程没有调用 `ssend`
或 `silent_close`，服务端只是在执行 SSH 协议要求的“收到 CLOSE 必须回
CLOSE”（外加一个 EOF）。也就是说，一个完全合规的服务端，在面对
“本端先关、立刻复用编号”的客户端时，天然就会产生这条把新通道毒死的报文。

之后：

- `libssh2_channel_eof()` 返回 1；
- `libssh2_channel_read_ex()` 返回 0（应用会误认为“命令正常结束、无输出”）；
- 事实上 B 从未收到任何关闭意图。

用 `nbpty` 请求产生的应答也可复现同样的提前关闭（矩阵中 “after-open” 系列
在注入 `CLOSE` 后均表现为 `remote.close, remote.eof`）。

### 3.10 同一通道上的陈旧应答（不需要复用）

```
### peer sends an *unsolicited* SUCCESS for this live channel
PKT 1 type=99 chan=0 len=5 head=0
### pty A (peer reply suppressed)
NBPTY rc=0 err=0            <-- 由陈旧 SUCCESS 判定成功
### dump c2
PKTCOUNT 1                  <-- 陈旧 SUCCESS 被消费
  peer replies dropped: [('SUCCESS', 0)]
```

说明 `ssh2_packet_requirev()`（`packet.c:1575`）的匹配键只有
“报文类型 + 4 字节通道号”，**不含请求序号/请求类型**，因此任何一条同类型的
旧应答都能满足任意请求。

### 3.11 释放后传输层永久卡死

把一条 DATA 报文留在 `outbuf` 中半发送状态，然后 `free` 通道：

```
sendpart 20
nbwrite A 1000 -> NBWRITE rc=-37
PENDING olen=9 osent=20 total=1044

free A -> FREE rc=-9 (API timeout expired)   [阻塞模式]
retry  -> FREE rc=-39 (BAD_USE)

open B -> OPENFAIL -9 API timeout expired    [发不出 OPEN]
PUMP   -> 接收方向仍然工作
```

`free` 在 `channel.c:2619` 需要 `ssh2_channel_close()`，后者要
`ssh2_transport_send()`，而 `transport_send_existing()`（`transport.c:936`）
因为新报文的 `data != p->odata` 一律返回 EAGAIN。只要调用方**再也没有机会
用原指针调用一次发送**（通道已被释放，这个指针永远不会再出现），
`olen` 就永远不会清零，**整个会话的发送方向永久不可用**，且用户可见的表现
只是 `open()` 超时。`s25_wedge_persist.py` 在非阻塞模式下连续 5 次
`free` 得到 `-37` 后转为 `-39 (BAD_USE)`，`PENDING` 始终是 `olen=9 osent=20`，
而接收方向（`pump`）仍然正常——这证明卡死只在发送方向且不可恢复。

`channel.c:2641` 的清理也不释放 `outbuf` 中属于该通道的 `odata`，
会话销毁前 `session->packet.odata` 一直是悬挂指针（`session.c:1024-1036` 只
释放 brigade 和 `payload`，不碰 `odata`）。

### 3.12 被动通道（forwarded-tcpip）：编号早分配 + 队列外可见性

`forwarded-tcpip` OPEN 在**发送 OPEN_CONFIRMATION 之前**就分配 `local.id`
（`packet.c:177`），但通道被挂进 **listener 的队列**而不是
`session->channels`（`packet.c:217-219`）：

```c
/* packet.c:177 */
channel->local.id = ssh2_channel_nextid(session);
...
/* packet.c:217-219，发送确认之后 */
ssh2_list_add(&listn->queue, &listen_state->channel->node);
listn->queue_size++;
```

实测（`s57`、`s58`、`s59`）：

```
### listen -> LISTEN rc=0
### peer opens forwarded-tcpip(sender=77) -> client assigns local=0
### listch -> LISTCH total=0        (队列中的通道不在 session->channels)
### peer sends DATA to local id 0 while queued
PKT 1 type=94 chan=0 len=21 head=9   <-- 报文进了 brigade（不是被丢弃）
### accept -> ACCEPTED local=0 remote=77
CH 0 ... local=0 remote=77 ... read_avail=12
### read -> READ rc=12 data="WHILE-QUEUED"
```

要点：

- **不会丢数据**：`ssh2_channel_locate()` 的第二段（`channel.c:93-101`）确实
  会遍历 listener 队列，所以 accept 之前的 DATA 会被正确归属到队列通道，
  数据不会丢失，这一点与“编号空洞”的直觉相反。
- **但编号仍然提前被 `next_channel` 消耗**：如果在这个窗口里 `next_channel`
  被回绕或被上层重置，新分配的会话通道可以拿到同号（`s51`/`s59` 用
  `setnext 0` 复现），此时两条通道共享编号；`read` 读取的是链表顺序上的
  第一条，因而出现跨通道串读：
  ```
  ### listch
  LISTCH 0 ptr=... local=0 remote=77
  LISTCH 1 ptr=... local=0 remote=0
  ### read session channel -> READ rc=21 data="PRE-ACCEPTLATE-QUEUED"
  ```
- 正常（不回绕）情况下 `next_channel` 已经加一，不会撞号；实测
  `s59`：队列通道 `local=0`、随后打开的会话通道 `local=1`，两者共存无冲突。

（`s51` 中的 `READ rc=21 data="PRE-ACCEPTLATE-QUEUED"` 是在**已经**用
`setnext 0` 制造撞号之后读到的，所以它同时包含“pre-accept 阶段写入的数据”
和“accept 之后再次写入的数据”；单独执行 `s57`（不撞号）只能读到
`"WHILE-QUEUED"`，数值为 12。）

因此 §4.2 中把它列为“串道触发条件”只在前述“编号被回绕/重置”的意义上成立；
**单独存在队列通道并不会造成串道**，这一点需要与 §3.3/§3.7 区分。

---

## 4. 判定

### 4.1 是否存在释放后使用（UAF）

| 场景 | 判定 | 证据 |
|---|---|---|
| `transportpacket.odata` 指向已释放通道成员（`write_packet` / `reqPTY_packet` / `adjust_adjust` / `close_packet`） | **存在**（悬挂指针，内容为 `outbuf` 已加密副本，通常不会读到该内存；但该指针永不清零） | §3.11，`STATE ... pending=0x.../9` 在 `FREE rc=0` 之后仍然存在；`session.c` 销毁时也不释放 `odata` |
| 忽略型扩展数据把传输层的 `readPack_state`/`fullpacket_state` 与 payload 留在会话上，`free` 只复位 `packAdd_state`/keeper | **存在**（结果不是空指针解引用，而是同一 payload 被当新报文二次解析、并按当前编号归属；实测 `PKT 2 type=95 chan=0` 归入新通道） | §3.6、`s53`、`s54` |
| `close_cb`（如 `sftp_dtor`）在 `ssh2_channel_close()` 中调用，而 `free` 之后迟到的 `CLOSE` 再次触发关闭逻辑 | **未复现**（`close_cb` 只在 `ssh2_channel_close()` 的 `rc != EAGAIN` 分支调用一次；`free` 路径不会二次调用） | `channel.c:2516-2518`、`channel.c:2619` |
| 迟到 `CHANNEL_CLOSE` 命中复用编号的新通道 | **存在**（逻辑错误，非内存错误） | §3.9 |
| 迟到 `SUCCESS/FAILURE` 被后续请求消费 | **存在**（逻辑错误） | §3.5、§3.10 |

关于 `odata` 的严重性需要精确表述：`ssh2_transport_send()` 在实际发送前已经把
待发数据**加密并复制**到 `session->packet.outbuf`（`transport.c:1130` 的
`memcpy(&p->outbuf[5], data, data_len)`），因此 `transport_send_existing()`
续发时读的是 `outbuf`，**不会**在正常路径上直接读已释放内存。危险在于：

1. `odata` 的“身份比较”只比地址和长度，不比对内容，于是**新的一次发送
   可以被误认为是旧报文的续发**（§3.8），导致本次数据被丢弃、对端收到陈旧
   数据，而 API 返回成功。
2. `olen` 永不清零 → 会话发送方向永久卡死（§3.11）。
3. 会话销毁后 `odata` 是悬挂指针，任何后续对 `session->packet` 的使用
   （例如 `session_free` 期间再次进入传输层）都会触及已释放对象。

### 4.2 是否存在迟到数据串入新通道

**存在，且可稳定复现**：§3.3（`STALE-DATA` / `SEEPED-INTO-NEW`）、
§3.4（`during-open` 阶段 `read_avail` 立即增长）、§3.7（回绕后同号双通道）、
§3.12（accept 后编号共享）。

触发条件按现实性排序：

1. **`next_channel` 回绕**：需要 2^32 次通道打开，实际极难；但 `uint32_t`
   回绕本身没有防护，且回绕后 `max(live)` 会**主动**制造撞号。
2. **上层代码重置 `next_channel`**（本仓实验所用手段；生产库中不可行，但
   可用来证明“只要撞号就串道”）。
3. **预备通道早入链**（`channel.c:167` / `packet.c:177/372/532`）造成的
   “编号已占用但通道未确认”窗口：这不是独立的撞号来源（预备通道仍然占着
   一个唯一的编号），但它让**已经撞号**的迟到报文能命中一个尚未完成
   `open()` 的通道，从而污染 `remote.id` 与窗口（§3.4 的 `during-open` 列）。
4. **listener 队列通道**（§3.12）：`next_channel` 在发送 OPEN_CONFIRMATION
   之前就被消耗；正常不回绕时不会撞号，但队列通道在 accept 之前不在
   `session->channels` 里，一旦编号被回绕/重置即可与它共享编号。

结论：**串道的必要条件只有一个——两条通道生命周期共享同一个
`local.id`**。§3.3/§3.7 证明这个条件一旦成立，所有数据/状态类报文都会串；
§3.4 证明它不必发生在 `open()` 完成之后。

### 4.3 是否存在错误状态残留

**存在**：

- `err_code = -23 (CHANNEL_UNKNOWN)` 被一次合法的迟到报文写入会话，且
  不会被 `free()` 或后续成功操作清掉；只有下一次进入 `ssh2_wait_socket()`
  （`session.c:565`，阻塞等待）才会复位。
- brigade 中永久残留 `SUCCESS`/`FAILURE`（§3.2、§3.5），数量可无限增长：
  实验中注入 500 条即得到 `PKTCOUNT 500`，再注入 500 条给未分配编号的应答
  得到 `PKTCOUNT 1000`，会话不报错、继续可用——这是**无界内存增长**。
- `remote.close`/`remote.eof`/`exit_status` 被旧报文污染（§3.4、§3.9）。
- `local.window_size` 被旧 `WINDOW_ADJUST` 抬高（§3.3），会破坏本端写窗口
  的流控（可能让本端发出超过对端窗口的数据）。

---

## 5. 修复建议（兼容合法关闭交错）

### 5.1 编号生命周期：引入“已关闭但未确认”的墓碑

最小侵入、兼容现有 API 的方案：

1. 在 `LIBSSH2_SESSION` 增加一个小的“已释放编号”集合
   （例如 32 项环形表 `struct { uint32_t id; } closed_ids[32]`，或按需哈希）。
   - `ssh2_channel_free()` 在摘链前把 `channel->local.id` 记入该表
     （**前提**：本地已 `local.close`，或已收到 `remote.close`）。
   - `ssh2_channel_nextid()` 不得分配表中出现的编号（跳过并继续 +1）。
   - `ssh2_packet_add()` 对所有通道类报文先查该表：命中则**静默丢弃并清
     `err_code`**，不查通道链表、不写 `remote.*`、不回 FAILURE。
   - 条目在以下任一条件满足时移除：收到对端针对该编号的 `CLOSE`；或该编号
     已经“确认关闭”（本地 close 且收到 remote close）；或超时/达到表容量时
     按 LRU 淘汰（淘汰后仍有回绕风险，但风险窗口被压缩到 N 个通道）。
2. 若不愿维护表，至少把 `next_channel` 改成**不回绕**（`UINT32_MAX` 时返回
   `LIBSSH2_ERROR_CHANNEL_OUTOFORDER` 并拒绝再开通道），并在
   `ssh2_channel_nextid()` 中把 `id = max(live)` **同时**与
   `session->next_channel` 做“取较大者”，而不是直接覆盖：
   ```c
   /* 现有实现里 id 可能被 max(live) 拉回，导致重复分配 */
   if(channel->local.id >= id)          /* 改成 >= 而不是 > */
       id = channel->local.id + 1;
   ```
   更稳妥的是维护独立的 `next_channel` 单调递增，绝不回退。

### 5.2 请求应答：按“编号 + 请求类型 + 序号”匹配

1. 修正如 §1.5 的号空间混用：`want_reply` 的 `CHANNEL_SUCCESS/FAILURE`
   应回送**对端的发送方编号**。`packet.c:1193` 现在是
   `memcpy(&packet[1], data + 1, 4)`（本端编号）；应改为使用该通道的
   `remote.id`（即 `channelp->remote.id`，找不到时按 §5.1 静默丢弃，
   而不是照抄）。
2. 为每个请求分配**单调递增的请求序号**（`uint32_t req_seq`），在
   `CHANNEL_REQUEST` 的扩展数据（或本地状态机中仅记录“最近一次请求的
   类型 + 序号”）记录；`ssh2_packet_requirev()` 的匹配条件加上“该通道无未完成
   请求时不得消费应答”。
3. 更直接的兼容修法：请求类 API 在发送请求后，**先把 brigade 中该通道上
   已有的 `SUCCESS`/`FAILURE` 全部丢弃**（或记录基线位置，只接受发送之后
   到达的应答）。这需要 `ssh2_packet_ask` 能返回位置，可在
   `struct packet` 增加 `uint64_t seq` 单调计数，并在请求开始时记下基线。
4. `CHANNEL_REQUEST` 的自动 `FAILURE` 回复（`packet.c:1188`）在
   `channelp == NULL` 时也会执行：因为 `want_reply` 分支在 `channelp`
   检查之外。实测（`s63.py`）向一个**不存在的** recipient channel 发
   `want_reply=1` 的请求，libssh2 仍回一条 FAILURE；若要偏离“必须回包”的
   RFC 字面要求，至少应在 `!channelp` 时**静默丢弃**（因为无法确定对方的
   编号语义），否则对端会把它当成另一条通道的应答。

### 5.3 `libssh2_channel_close()` 的返回语义

- 当前实现把 `ssh2_transport_read()` 的**任何非 EAGAIN 返回值**都当成
  “等待结束”：读到的第一条报文若不是 CLOSE（如对端先发 EOF），`close()`
  会在 `remote.close == 0` 时返回 0。建议在 `channel.c:2503` 的分支里改为
  “只有 `remote.close` 为真、socket 已断开、或超时/明确错误时才退出”，
  并显式把“读到了别的报文”当作继续循环。
- 若要保持向后兼容（`close()` 不阻塞），则 `free()` 必须保证对端 CLOSE
  不会错投：即执行 §5.1 的墓碑检查，或在 `free()` 前把“等待对端 CLOSE”
  的结果记录到墓碑，使迟到 CLOSE 被安全吞掉。
- 文档 `docs/libssh2_channel_close.md` 已说明“对端可能继续发数据直到它
  回送 close，随后可调用 wait_closed”；应补充：“若不等 `wait_closed()`，
  本端编号在收到对端 CLOSE 前不得复用”。

### 5.4 传输层待发报文的身份

1. `transport_send_existing()`（`transport.c:936`）的“指针 + 长度”比较不足。
   增加一个 `uint64_t opkt_id`：`transportpacket` 记录当前待发报文的序号，
   `ssh2_transport_send()` 每次以新序号发起，续发必须同序号；不再依赖
   `odata` 的地址。
2. `ssh2_channel_free()` 前检查 `session->packet.olen` 是否指向
   本通道成员；若是，要么先完成发送，要么显式放弃该待发报文
   （`p->olen = 0; p->odata = NULL; p->ototal_num = 0;`）并**重置
   `session->local.seqno` 相关的一致性**——放弃一个已部分发送的 SSH 报文会
   破坏传输层字节流，因此更安全的是**禁止释放**：`free()` 返回
   `LIBSSH2_ERROR_EAGAIN` 直到该报文发送完毕（当前行为即如此，但用户会
   看到永久卡死）。
3. 为定长缓冲区分“新发送”与“续发”：在 `channel.c` 的
   `channel_request_pty_size`（`channel.c:1195`）等处，若 `reqPTY_state`
   不是 `created`，**必须重新填充缓冲区**，而不是让传输层用它做身份判断。

### 5.5 忽略型扩展数据的续跑

- `ssh2_channel_free()` 除清 `packAdd_channelp` 外，还必须把会话的
  `readPack_state`、`fullpacket_state` 复位，并释放/接管
  `session->packet.payload`（当前只有 `transport_fullpacket()` 的 EAGAIN
  分支会清它，见 `transport.c:358-365`）。
- 更根本的修法：`ssh2_packet_add()` 的 `jump1` 续跑点**不应依赖通道指针**。
  把“待调整的通道编号与字节数”存成值，续跑时重新 `ssh2_channel_locate()`；
  `locate` 失败则直接丢弃（`CHANNEL_UNKNOWN` 不能写入 `err_code`，见 §5.7）。
- 另外，`packet.c:995` 的 EAGAIN 返回会让 `data`（== `payload`）既没有被
  入队也没有被��放，同时又留下 `packAdd_state = jump1`；这与
  `transport.c:358` 的注释“data 已由 brigade 拥有”相矛盾。应统一为
  “EAGAIN 期间 payload 由 transport 独占”，并在 `free` 通道时一并清理。

### 5.6 预备通道的生命周期

- `channel.c:167` 的 `ssh2_list_add` 应推迟到收到 OPEN_CONFIRMATION 之后；
  在此之前用一个**独立的 `session->opening_channel` 字段**（现有
  `session->open_channel` 正是如此）承载，并让 `ssh2_channel_locate()` 在
  匹配“尚未确认”的通道时**拒绝接收数据类报文**（返回 NULL / 静默丢弃），
  而不是交给一个还没有窗口/PacketSize 的通道。
- 被动通道（`packet.c:177` 等）同理：先确认发送成功，再挂链。

---

## 6. 可复验的安全判据

以下判据全部可由仓库内代码或附录 A 的实验脚本机械复验；每条都在本仓
实验中给出了当前的失败/通过结论。

| # | 判据 | 当前结论 | 复验方法 |
|---|---|---|---|
| C1 | 释放通道后，任何携带该编号的 `DATA`/`EXTENDED_DATA` 都不得增加任何活跃通道的 `read_avail` | **失败**（§3.3：`READ rc=19 data="OLD-CHANNEL-PAYLOAD"`） | `s52 R1`、`s02_reuse.py` |
| C2 | 释放通道后，任何携带该编号的 `WINDOW_ADJUST` 都不得改变任何活跃通道的 `local.window_size` | **失败**（§3.3/3.4：`local_window=3145728`） | `s52 R2`、`matrix2.py` |
| C3 | 释放通道后，任何携带该编号的 `exit-status`/`exit-signal` 都不得改变任何活跃通道的 `exit_status` | **失败**（§3.4/3.5：`status=42`） | `s52 R3`、`s18` |
| C4 | 释放通道后，任何携带该编号的 `CHANNEL_CLOSE`/`CHANNEL_EOF` 都不得把活跃通道标记为 `remote.close/eof` | **失败**（§3.9：新通道 `rclose=1`） | `s43`、`s31` |
| C5 | 一次请求的成功/失败必须由对端对该请求的应答决定；屏蔽对端应答时请求不得成功，且 brigade 不得残留可被后续请求消费的 `SUCCESS/FAILURE` | **失败**（§3.5/3.10） | `s28`、`s37` |
| C6 | `libssh2_channel_free()` 成功返回后，会话的发送方向必须仍然可用（`libssh2_channel_open_session()` 能在超时内成功） | **失败**（§3.11：`OPENFAIL -9`） | `s25` |
| C7 | `libssh2_channel_free()` 成功返回后，`session->packet.olen` 必须为 0，且 `odata` 不指向已释放内存 | **失败**（§3.11：`PENDING olen=9`） | `s25`、`s39` |
| C8 | `ssh2_channel_nextid()` 返回的编号必须与其时 `session->channels` 及所有 listener 队列中的编号都不重复 | **失败**（§3.7） | `s48`、`s51` |
| C9 | 一次 `ssh2_transport_send()` 只应发送本次调用的数据；同一缓冲区的新调用不得被当作旧报文的续发 | **失败**（§3.8：对端收到 111 而非 222） | `s45` |
| C10 | 一次合法的迟到报文（对端已关闭的通道编号）不得把 `session->err_code` 改成 `-23` | **失败**（§3.2） | `s09`、`s52` |
| C11 | brigade 长度在持续的迟到报文下必须有界 | **失败**（§4.3：1000 条） | `s23` |
| C12 | 忽略型扩展数据的窗口调整在发送 EAGAIN 后，若通道被释放，传输层不得以同一 payload 再次调用 `ssh2_packet_add()` 并按当前编号归属 | **失败**（§3.6：`readPack=11`/`fullpacket=2` 残留，旧 payload 以 `chan=0` 二次入队） | `s53`、`s54` |

判据的可执行形态（建议作为回归测试）：

```c
/* C1 伪代码 */
ch = libssh2_channel_open_session(s);
libssh2_channel_close(ch);
libssh2_channel_free(ch);
peer_send(SSH_MSG_CHANNEL_DATA, ch->local.id /* 旧编号 */, "X", 1);
ch2 = libssh2_channel_open_session(s);   /* 无论是否复用编号 */
drain_session(s);
assert(libssh2_channel_read(ch2, buf, sizeof buf) != 1);
```

注意：`ch` 在 `free` 后不可再解引用，旧编号需在 `free` 前保存。

---

## 7. 附录 A：实验脚本

源码与脚本位于 `/tmp/ssh-late-796/work`（不在仓库内，避免污染源码树）。
核心文件：

| 文件 | 作用 |
|---|---|
| `client.c` | 含 `libssh2_priv.h` 的受控客户端；`dump`/`pump`/`nonblock`/`sendfail`/`sendpart`/`setnext`/`listch`/`extpacket` 等命令 |
| `run.py` | paramiko 伪造服务端 + 客户端进程编排；`ssend()` 注入任意通道报文；`silent_close()` 抑制 paramiko 自动回 CLOSE；`srvlog` 记录服务端视角 |
| `s01`…`s66*.py` | 各实验场景（编号即报告中的 `sNN` 引用）；每个文件自包含，可用 `-I -u` 单独运行 |
| `README.md` | 上述文件的构建/运行说明 |
| `matrix2.py`、`s40_final_matrix.py` | 阶段 × 报文类型 / 关闭时序 × 报文类型矩阵 |
| `verify.sh` | 一键重跑 §6 的关键判据 |

复现（在 `.../work` 内）：

```sh
/tmp/venv2/bin/python -I -u s52_summary_check.py   # R1–R7
/tmp/venv2/bin/python -I -u matrix2.py             # 阶段 × 类型矩阵
/tmp/venv2/bin/python -I -u s40_final_matrix.py    # 关闭时序 × 类型矩阵
/tmp/venv2/bin/python -I -u s28_definitive.py      # 陈旧应答被消费
/tmp/venv2/bin/python -I -u s43_close_returns_early.py  # 对端回送 CLOSE 毒化新通道
/tmp/venv2/bin/python -I -u s25_wedge_persist.py   # 发送方向永久卡死
```

所有脚本读取环境变量 `CLIENT_BIN`（默认 `./client`）。

构建（未修改源码）：

```sh
cmake -S <repo> -B /tmp/ssh-late-796/build \
      -DBUILD_SHARED_LIBS=OFF -DENABLE_DEBUG_LOGGING=ON \
      -DCMAKE_BUILD_TYPE=Debug -DBUILD_EXAMPLES=OFF -DBUILD_TESTING=OFF
cmake --build /tmp/ssh-late-796/build -j8
```

> 注意：客户端必须与库使用一致的 `LIBSSH2DEBUG` 定义，否则
> `LIBSSH2_SESSION` 布局不同，`dump` 会读到错误的字段（本仓第一次实验即
> 因此误判 `packAdd_state`；修正后结论如 §3.6 所示）。

## 8. 附录 B：关键代码索引

| 主题 | 位置 |
|---|---|
| 编号分配（含回绕） | `src/channel.c:51-73` |
| 编号查找（无墓碑） | `src/channel.c:79-105` |
| 主动打开时提前入链 | `src/channel.c:133`、`src/channel.c:167` |
| 被动打开时提前分配编号 | `src/packet.c:177`、`src/packet.c:372`、`src/packet.c:532` |
| `free` 的报文清理（仅 DATA/EXT） | `src/channel.c:2641-2648` |
| `free` 清 `packAdd_channelp` | `src/channel.c:2681-2684` |
| `close` 的等待与提前返回 | `src/channel.c:2503-2521` |
| EOF 发送 | `src/channel.c:2319-2340` |
| 数据/扩展数据分发 | `src/packet.c:924-952` |
| EOF 分发 | `src/packet.c:1062-1078` |
| REQUEST/exit-status 分发与自动 FAILURE | `src/packet.c:1087-1205` |
| 回包抄本端编号 | `src/packet.c:1188-1195` |
| CLOSE 分发 | `src/packet.c:1211-1229` |
| WINDOW_ADJUST 分发 | `src/packet.c:1297-1324` |
| `packet_ask` 的匹配键 | `src/packet.c:1395-1425` |
| `packet_requirev` | `src/packet.c:1575-1620` |
| 忽略型扩展数据 + jump1 | `src/packet.c:965-1006` |
| 传输层续发身份校验 | `src/transport.c:922-990` |
| `readPack_state == jump1` 续跑 | `src/transport.c:450-470` |
| 待发报文字段 | `src/libssh2_priv.h:642-646` |
| 定长待发缓冲 | `src/libssh2_priv.h:496,522,532,538` |
| SFTP 的 `close_cb` | `src/sftp.c:737-753`、`src/sftp.c:991` |
| 会话销毁时 brigade 清理 | `src/session.c:1024-1036` |
| `err_code` 的清除点 | `src/session.c:565` |
