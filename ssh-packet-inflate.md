# libssh2: zlib 压缩报文解码的长度、错误传播与内存放大排查

- 代码版本：`e75fa9a`（`task/72` 分支，工作区干净）
- 构建：`cmake -DENABLE_ZLIB_COMPRESSION=ON -DCRYPTO_BACKEND=OpenSSL`，
  `LIBSSH2DEBUG` 打开；另建一份 `-fsanitize=address,undefined` 副本
- 平台：Linux 6.8，zlib 1.3，gcc 13.3
- 测试手段：本机伪服务端（桩 socket + 真实 `ssh2_transport_read()` /
  `comp_method_zlib_decomp()`）+ 本机 OpenSSH 9.6p1 合法基线
- 所有实验脚本都在 `/tmp/pktlab/`，**没有**放进仓库，也没有改动任何产品代码

---

## 0. 结论摘要

| # | 结论 | 严重度 |
|---|------|--------|
| 1 | `LIBSSH2_PACKET_MAXDECOMP`（40000）**不是硬上限**。实际可交付的单个报文解压长度最高达 `2*40000-1 = 79999` 字节，超限 100% | 中 |
| 2 | 该上限是**阶梯函数**，取决于压缩后长度而不是解压后长度，导致"更小的载荷被拒、更大的载荷被接受"的非单调行为 | 中 |
| 3 | 解压超限/解压失败后，`socket_state` 仍为"已连接"，zlib 流进入**永久错误态**；同一会话上后续每一个合法报文都返回同一个错误，且**永远不会自愈**，只有重新 kex（`dtor`+`init`）才能恢复 | 中 |
| 4 | `ssh2_transport_read()` 的失败被 `libssh2_poll()` 的 `while(... > 0);` 空循环**静默丢弃**：实测 `poll()` 返回 0 个事件，错误只在 `session->err_code` 里；会话随后永久"活着但安静" | 中 |
| 5 | `session->packets` 报文队列**没有任何上限**：每 201 字节线速报文在堆上滞留 ~112 KB，实测 369 KB 上线 → 90 MB 堆（244x）。认证前配 `zlib` 时同样可达 | 高（本地 DoS） |
| 6 | 跨报文流被切断时，**会交付"看似合法"的截断报文**：`packet.c` 信任报文内嵌的长度字段，实测交付了一个自称 500 字节、实际 11 字节的 `SSH_MSG_CHANNEL_DATA` | 低（丢数据/协议不严谨） |
| 7 | 零输出报文（合法的空 flush 块、纯 zlib 头）被判为 `LIBSSH2_ERROR_PROTO`，与"跨报文延续"的合法语义冲突 | 低（互操作） |
| 8 | 解压结果超过 `channel->remote.packet_size` 时被静默截断（`datalen` 缩短至 32777），传输层仍返回成功，调用方无从得知丢了多少字节 | 低 |
| 9 | **未发现**内存破坏：ASAN + UBSAN 全量跑通，无越界/泄漏/UAF。解压缓冲区始终在 `payload_limit` 内增长，`SSH2_SAFEFREE` 之后没有复用脏指针 | — |

最值得修的是 #5（无限队列）与 #2/#1（上限不实），二者合用构成放大链：
**低带宽高压缩比输入 → 超限接受 → 滞留队列 → 无界增长**。

---

## 1. 相关代码路径

### 1.1 解压入口

`src/comp.c:199-299` `comp_method_zlib_decomp()`：

```c
/* comp.c:212-227 —— 初始缓冲区 = 4*src_len，再夹到 payload_limit */
if(src_len <= SIZE_MAX / 4)
    out_maxlen = (uInt)src_len * 4;
else
    out_maxlen = payload_limit;
if(out_maxlen < 25)     out_maxlen = 25;
if(out_maxlen > payload_limit) out_maxlen = payload_limit;
...
strm->next_out = SSH2_ALLOC(session, (uInt)out_maxlen);   /* comp.c:231 */
strm->avail_out = (uInt)out_maxlen;
```

关键点：**初始缓冲区按压缩后长度估算**，而不是按"允许解压到多大"。

### 1.2 增长与上限检查

```c
/* comp.c:238-293 */
for(;;) {
    status = inflate(strm, Z_PARTIAL_FLUSH);              /* comp.c:244 */
    if(status == Z_OK) {
        if(strm->avail_out > 0) break;   /* 输出没写满 -> 完成 */
    }
    else if(status == Z_BUF_ERROR) {
        if((out_maxlen - strm->avail_out) == 0) { /* 零输出 */ ... error }
        break;
    }
    else { ... error }                                    /* comp.c:266 */
    if(out_maxlen > payload_limit || out_maxlen > SIZE_MAX / 2) {
        ... error "Excessive growth in decompression phase"   /* comp.c:275 */
    }
    out_ofs = out_maxlen - strm->avail_out;
    out_maxlen *= 2;                                      /* comp.c:283 */
    newout = SSH2_REALLOC(session, out, out_maxlen);      /* comp.c:284 */
    ...
    strm->avail_out = (uInt)(out_maxlen - out_ofs);
}
```

`payload_limit` 只在**缓冲区写满、即将翻倍时**才被检查。也就是说，
缓冲区最后一次可以合法地从 `<= limit` 翻倍到 `2*limit`，而在这块
`2*limit` 缓冲区被填满之前不会再检查一次。因此单报文可接受的解压长度上限是
`2*limit - 1`。

### 1.3 长度交付给上层

`src/transport.c:311-338`：

```c
compressed = session->remote.comp && session->remote.comp->compress &&
             ((session->state & SSH2_STATE_AUTHENTICATED) ||
              session->remote.comp->use_in_auth);   /* transport.c:312-315 */

if(compressed && session->remote.comp_abstract) {
    rc = session->remote.comp->decomp(session, &data, &data_len,
                                      LIBSSH2_PACKET_MAXDECOMP,  /* :328 */
                                      p->payload,
                                      session->fullpacket_payload_len,
                                      &session->remote.comp_abstract);
    SSH2_SAFEFREE(session, p->payload);
    if(rc) return rc;                       /* :333-334 错误直接上抛 */
    p->payload = data;
    session->fullpacket_payload_len = data_len;   /* :337 用解压后长度覆盖 */
}
if(session->fullpacket_payload_len < 1) { ... PROTO }   /* :341 */
session->fullpacket_packet_type = p->payload[0];        /* :346 */
```

重要观察：

- `data_len` 是 **`decomp()` 自己报告的**，上层不再校验它是否 `<= 40000`。
  `LIBSSH2_PACKET_MAXDECOMP` 只是传给解压器的建议上限。
- 解压后长度完全取代了原始报文长度传入 `ssh2_packet_add()`，
  也就是 L2 长度与 L3 解压长度之间**没有交叉校验**。
- `payload_limit` 的语义是"解压后允许多大"，而 `LIBSSH2_PACKET_MAXPAYLOAD`
  的语义是"线上报文允许多大"。两者取值都是 40000，但**代码里从未比较两者**。

### 1.4 队列交付

`src/packet.c:1332-1345`：未在 `switch` 中显式处理的报文类型一律进入
`session->packets` 链表：

```c
packetp->data     = data;
packetp->data_len = datalen;
packetp->data_head = data_head;
ssh2_list_add(&session->packets, &packetp->node);
```

这是唯一没有容量检查的队列；`channel->read_avail` 受 `window_size` 约束，
但 **brigade 本身不受任何约束**。

### 1.5 出错后的状态

`src/transport.c:460` 只在 `session->socket_state == SSH2_SOCKET_DISCONNECTED`
时拒绝继续；解压错误路径（`:334`）**不设置** `socket_state`，也不清
`remote.comp_abstract`。所以 zlib 的 `Z_DATA_ERROR`/自定义"过度增长"错误之后，
流对象保持错误状态，下一次 `inflate()` 继续返回同一个错误。

---

## 2. 实测：长度、错误与内存

### 2.1 单个报文（伪服务端，桩 socket，计数器分配器）

```
MAXDECOMP=40000  MAXPAYLOAD=40000  MAX_SSH_PACKET_LEN=35000
```

| 用例 | 压缩长度 | 解压后交付 | 峰值堆 | 读取后滞留堆 | 返回 | socket |
|------|---------:|-----------:|-------:|-------------:|------|--------|
| A 普通 1000 字节载荷 | 1008 | 1000 | 37812 | 36848 | 正数（已交付） | 已连接 |
| B 40001 字节（超限 1 字节） | 15396 | **40001** | 128168 | 112816 | 正数（已交付） | 已连接 |
| C 79999 字节 | 30775 | **79999** | 143547 | 112816 | 正数（已交付） | 已连接 |
| D 80000 字节 | 30773 | 0 | 143545 | 32768 | `ZLIB(-29)` | 已连接 |
| E 200 MiB 全零，送 39995 字节 | 39995 | 0 | 152767 | 32768 | `ZLIB(-29)` | 已连接 |
| F 合法空 flush 块（7 字节） | 7 | 0 | 39 | 0 | `PROTO(-14)` | 已连接 |
| G 64 字节 0xff（脏流） | 64 | 0 | 324 | 0 | `ZLIB(-29)` | 已连接 |
| H 完整流（`Z_STREAM_END`） | 19 | 0 | 34007 | 32768 | `ZLIB(-29)` | 已连接 |

说明：

- "峰值堆"是本次 `ssh2_transport_read()` 期间分配器的瞬时高水位增量；
- "滞留堆"是该次读取结束后仍然占用的字节（主要是交付出去的载荷 + zlib 32 KiB 窗口）；
- 滞留的 32768 是 zlib 的 inflate 窗口，首次 `inflate()` 惰性分配，实测一次
  `inflateInit` 合计 7272 字节（其中窗口 7160），窗口在第一次输出时扩到 32768。

### 2.2 上限的精确形状

`decomp()` 判决只取决于**压缩后长度落在哪一档阶梯**。下表由
`/tmp/pktlab/ceiling.c`（逐字复刻 `comp.c:212-293` 的预算逻辑，再与真实
`decomp()` 对拍）实测得到，`limit = 40000`：

| 解压后目标 | 压缩后长度 | 阶梯（初始→翻倍） | 可接受上限 | 实测 |
|-----------:|-----------:|-------------------|-----------:|------|
| 40000 | 15395 | 40000→80000 | 79999 | 接受 |
| 40001 | 15396 | 40000→80000 | 79999 | 接受 |
| 50000 | 788 | 3152→…→50432 | 50431 | 接受 |
| 50000 | 1385 | 5540→…→44320 | 44319 | **拒绝** |
| 50000 | 1973 | 7892→…→63136 | 63135 | 接受 |
| 60000 | 930 | 3720→…→59520 | 59519 | **拒绝** |
| 60000 | 2348 | 9392→…→75136 | 75135 | 接受 |
| 70000 | 1071 | 4284→…→68544 | 68543 | **拒绝** |
| 70000 | 2723 | 10892→…→43568 | 43567 | **拒绝** |
| 70000 | 4840 | 19360→…→77440 | 77439 | 接受 |
| 79999 | 30775 | 40000→80000 | 79999 | 接受 |
| 80000 | 30773 | 40000→80000 | 79999 | **拒绝** |

由此得到**非单调**行为（同一会话、同样 40000 的限额）：

```
payload=70000  src=1071   -> REJECTED   (上限 68543，但阶梯停得太早)
payload=70000  src=2723   -> REJECTED   (上限 43567)
payload=50000  src=1385   -> REJECTED   (上限 44319)
payload=50000  src=1973   -> accepted   (50000 < 63135)
payload=79999  src=30775  -> accepted   (79999 == 2x 上限 - 1)
```

即：**同一条流里，50000 字节的载荷能不能过，取决于它是怎么被压缩的；
"上限 40000"这个数字在语义上已经失去意义。**

### 2.3 错误传播

```
包 #1  0xff junk          -> rc=-29 (ZLIB)     socket_state=0 (connected)
包 #2  合法、全新流        -> rc=-29 (ZLIB)     socket_state=0
包 #3  合法、全新流        -> rc=-29 (ZLIB)     socket_state=0
包 #4  合法、全新流        -> rc=-29 (ZLIB)     socket_state=0
err_msg = "decompression failure"
```

- 承载这份报文的 **MAC 校验是通过的**（攻击者/服务端自己算的），所以
  这不是"损坏数据"，而是"合法帧 + 非法压缩流"。协议层无法区分。
- 之后正确做法只有重新 kex（`kex.c:340-354` 在每个 NEWKEYS 时
  `dtor` + `init`）。实测：显式 `dtor`+`init` 之后同一会话语义恢复正常
  （`rc=正数, payload_len=1000`）。
- 期间所有上层 API 都失败，但 **`socket_state` 仍是"已连接"**，
  常规的"连接已死"判断（`transport.c:460`、`sftp.c:483`、
  `packet.c:1479`）全部不成立，调用方会一直重试。

`libssh2_poll()` 的丢弃问题（`src/session.c:1700-1704` 与 `1770-1774`）：

```c
while(ssh2_transport_read(fds[i].fd.channel->session) > 0);
```

实测（`/tmp/pktlab/pollstuck.c`，走公开的 `libssh2_poll()`）：

```
poll #1: rc=0 channel.revents=0x0 socket_state=0
  session err=decompression failure (code -29) -- error not surfaced to poll caller
later transport read: rc=-29 (same error, socket_state=0)
idle transport read: rc=-37 (EAGAIN=-37)
poll #2 (idle, wedged): rc=0 channel.revents=0x0
```

即：`poll()` 第一次就报告"没有事件"（`rc=0`、`revents=0`），错误只落在
`session->err_code`；之后 socket 上再没有新数据，`transport_read()` 返回
`EAGAIN`，`poll()` 继续报告无事件。会话看起来"活着且安静"，
但再也不会产生任何数据。应用若按 `poll()` 结果驱动，会永久等待。

### 2.4 内存放大：无界队列

用 200 字节左右的线上报文（每个解压出 40000 字节，未处理的报文类型
`0x64` 只能进 brigade），应用一直不读：

```
packets=1     wire=184      live_heap=77616      queued=1
packets=100   wire=18456    live_heap=4531904    queued=100
packets=500   wire=92280    live_heap=22528448   queued=500
packets=1000  wire=184560   live_heap=45024128   queued=1000
packets=2000  wire=369120   live_heap=90015488   queued=2000
final: 369120 wire bytes -> 90015488 heap bytes (244x)
after session_free: 0
```

`kex.c` 协商到 `zlib`（`use_in_auth = 1`）时，认证前同样成立
（驱动真实的 `ssh2_packet_requirev()` 循环）：

```
pre-auth: AUTHENTICATED 未置位, use_in_auth=1 -> 解压已启用
pkts=1500  wire=277692  live_heap=67737920  queued=1500
RESULT: 277692 wire -> 67737920 heap (244x), still unauthenticated=1,
        socket=0 (connected)
```

用**字典预热**还能把每个报文的成本压得更低：先发一个全 `A` 的合法报文
把 zlib 窗口填满，之后每个 40000 字节的延续报文只需 ~192 字节压缩数据
（208x），对应 ~112 KB 滞留堆，即 **~561 倍**每报文的放大。
实测（`/tmp/pktlab/dict.c`）：

```
primed packet: 195 compressed -> 40000 bytes
continuation:  192 compressed -> 40000 bytes  (208.3x)
per-packet heap retained ~112768 bytes for 201 wire (561x)
```

也就是说，攻击者用约 6 KB/s 的带宽（每秒约 30 个 201 字节报文），
一分钟就能让客户端堆增长 ~203 MB；总量没有上界，直到进程 OOM。
用 2.4 节实测的 244x 保守估计，1 MB 上线流量即可让堆增长约 244 MB。

**注意**：这个放大器只在应用"不读"或"读得比收得慢"时成立；一旦应用调用
`libssh2_channel_read()`，`channel.c:1960-1963` 会 `do { rc =
ssh2_transport_read(); } while(rc > 0);` 一次性把 socket 上的所有报文
读进来并排队，队列只会更长——**读得越勤，堆积越快**。
（真正缩短队列的只有 `channel_read()` 里按 channel 匹配消费的分支，
`channel.c:2011-2046`；不匹配的报文永远留在链表里。）

### 2.5 截断后仍被当作合法报文交付

构造：一条真正合法的 `SSH_MSG_CHANNEL_DATA`（491 字节数据、声明长度 500），
压缩后 41 字节。攻击者把压缩流切在第 19 字节，让第一个报文只解压出
20 字节，第二个报文解压出余下的 480 字节：

```
legal message: 509 bytes, compressed to 41
attacker split: first = 19 compressed bytes (20 decompressed), second = 22

packet 1: transport rc=94, queued type=94 len=20
  embedded channel id=0
  embedded data-length field (claimed by the message)=500
  actual bytes present after the 9-byte header=11
  -> packet.c accepted it: rc=94, read_avail=11

packet 2: transport rc=85, queued type=85 len=489
  embedded data-length field=1514226243, actual bytes=480
  first byte of claimed data = 0x44 (mid-message)
```

- L2 帧完整、MAC 正确，L3 载荷是"一条报文的**前缀**"，但
  `packet.c:936-1002` 只校验 `datalen >= data_head`，从不比对
  内嵌的 `string` 长度字段与 `datalen`。
- 结果：应用收到一个自称 500 字节、实际只有 11 字节的
  `CHANNEL_DATA`；第二个报文的首字节是 0x55（消息中间的任意字节），
  被当作未知类型塞进 brigade。
- 这解释了为什么 1.x 系列必须在 `decomp()` 内部"恰好"断在 flush 边界上
  才安全——而代码**从未验证**这个前提。

顺带发现的同类问题：即使解压结果本身完整、也确实是合法的一帧，
`packet.c:1011-1017` 会因为超过 `channel->remote.packet_size`（默认 32768）
而**截短 `datalen` 并把 `session->err_code` 记成 `CHANNEL_PACKET_EXCEEDED`，
但仍返回成功**。实测一条解压后 60009 字节的 `CHANNEL_DATA`：

```
decompressed payload=60009 bytes (channel packet_size 32768)
transport rc=94 (>=1 means a packet was accepted)
queued data_len=32777  read_avail=32768
err=Packet contains more data than we offered to receive, truncating (code -25)
```

调用方只看到"成功收到一个 channel 数据包"，实际上 27232 字节（60009 - 32777）被丢弃；
RFC 4253 允许"MAY ignore bytes beyond packet_size"，但实现上应当让调用方
能区分"忽略"与"正常"，目前只有 `session->err_code` 侧信道能看出来。

### 2.6 合法跨报文流与零输出

实测合法的跨报文流本身工作正常：

| 场景 | 结果 |
|------|------|
| 3 个报文各在一个 `Z_PARTIAL_FLUSH` 边界 | 逐包交付 1000/1000/1000，正确 |
| 3 个报文在同一 TCP 段内 | 逐包交付 1000/1000，正确 |
| 同一压缩流被切入一个 deflate block 内部 | 交付 17 + 983 = 1000，**内容正确但被拆成两包** |
| 头部 2 字节（仅 zlib 头）单独成包 | `PROTO(-14)`，随后的包正常 |
| 合法空 flush 块（`Z_SYNC_FLUSH`，0 输出） | `PROTO(-14)` |
| 截断尾部（41→38 字节） | 交付 801 字节，**静默丢 199 字节** |

即：

- **零输出报文被判非法**（`comp.c:255-262` 的 `Z_BUF_ERROR` 且
  `out_maxlen - avail_out == 0` 分支）。可 `Z_SYNC_FLUSH` 在没有新数据时
  产生的正是这样的块，OpenSSH 也会发。这不是"恶意输入"专属。
- 截断尾部（`comp.c:252-264`）走 `Z_BUF_ERROR` 分支就 `break`，
  **不区分"输入耗尽"与"流被截断"**，于是交付了前缀，丢掉了余下的数据。
- `inflate(strm, Z_PARTIAL_FLUSH)` 会一直消费到输入耗尽，
  一个报文里有多个 flush 块时全部合并到一个输出里（实测 128 字节 = 64+64，
  合法）。

### 2.7 内存安全

ASAN + UBSAN（`-fsanitize=address,undefined`，`detect_leaks=1`）跑完全部
探针（`harness`、`phase2/3/5/6/7/9/10/12/14/15/16/17`、`final`、
`truncated`）：

- 无 heap-buffer-overflow、无 use-after-free、无 UBSan 报告；
- 每个 session 释放后 `live heap = 0`（唯一一条 LeakSanitizer 报告
  出现在我自己的测试桩里，已修正）；
- `SSH2_SAFEFREE` 之后 `p->payload` 为 NULL（`libssh2_priv.h:230-235`），
  错误路径不会带着脏指针复用；
- 增长上限 `out_maxlen > SIZE_MAX/2` 阻止了 `*2` 溢出；
- `comp_method_zlib_alloc` 有 `items*size` 溢出检查（`comp.c:112-114`）。

所以**这不是内存破坏漏洞**，而是**资源上限与状态机语义**的问题。

---

## 3. 问题定位（按代码位置）

| 位置 | 问题 |
|------|------|
| `src/comp.c:212-227` | 初始缓冲区按 `4*src_len` 估算，导致上限随压缩率浮动 |
| `src/comp.c:275-279` | 上限只在翻倍前检查，`2*limit` 区间成为合法输出区 |
| `src/comp.c:252-264` | `Z_BUF_ERROR` 既表示"输入耗尽"也表示"流被截断"，不区分 |
| `src/comp.c:255-262` | 零输出被当作错误（与 `Z_SYNC_FLUSH` 空块冲突） |
| `src/comp.c:266-273` | 任何 `Z_DATA_ERROR` 都不复位流，流进入永久错误态 |
| `src/comp.c:295-298` | 返回长度未经二次校验就交给上层 |
| `src/transport.c:326-337` | 不比较 `data_len` 与 `LIBSSH2_PACKET_MAXPAYLOAD`/`MAXDECOMP` |
| `src/transport.c:333-334` | 错误直接上抛，不标记连接不可用 |
| `src/packet.c:1011-1017` | 超过 `remote.packet_size` 时静默截断 `datalen`，仍返回成功 |
| `src/packet.c:936-1002` | `CHANNEL_DATA` 不校验内嵌长度字段与 `datalen` |
| `src/packet.c:1332-1345` | brigade 入队无容量上限 |
| `src/session.c:1700-1704,1770-1774` | `poll()` 用 `while(... > 0);` 吞掉错误 |
| `include/libssh2.h:196,200,204` | `MAXCOMP/MAXDECOMP/MAXPAYLOAD` 三个常量语义重叠且未被真正强制 |

---

## 4. 修复建议

### 4.1 把"上限"变成硬约束（最小改动，收益最大）

关键是**要让"恰好等于上限"和"超过上限"可区分**。当前代码区分不了，因为
`inflate()` 在缓冲区刚好写满时也返回 `Z_OK` 且 `avail_out == 0`，
与"还有更多输出"完全一样。最省事的办法是多留 1 字节：

```c
/* comp.c:212-227：初始分配与上限都改成 limit + 1 */
#define SLACK 1
size_t cap = payload_limit + SLACK;      /* payload_limit 远小于 SIZE_MAX */

if(src_len <= SIZE_MAX / 4)
    out_maxlen = (uInt)src_len * 4;
else
    out_maxlen = cap;
if(out_maxlen < 25)     out_maxlen = 25;
if(out_maxlen > cap)    out_maxlen = cap;

/* comp.c:275-293：增长一律不超过 cap */
if(out_maxlen >= cap) {
    SSH2_FREE(session, out);
    return ssh2_err(session, LIBSSH2_ERROR_ZLIB,
                    "decompressed payload exceeds limit");
}
next = out_maxlen * 2;
if(next > cap) next = cap;
...
/* comp.c:295-298：交付前做最终判定 */
*dest_len = out_maxlen - strm->avail_out;
if(*dest_len > payload_limit) {          /* 用掉了那个 slack 字节 */
    SSH2_FREE(session, out);
    *dest = NULL; *dest_len = 0;
    return ssh2_err(session, LIBSSH2_ERROR_ZLIB,
                    "decompressed payload exceeds limit");
}
*dest = out;
```

要点：

1. 分配上限恒为 `payload_limit + 1`，可交付长度恒 `<= payload_limit`；
2. **恰好等于 `payload_limit` 的合法载荷仍被接受**（实测 `want=40000`
   目前能过，修复后必须保持），`payload_limit + 1` 才被拒；
3. 交付前再做一次 `*dest_len <= payload_limit` 的终检，防止将来改动回退；
4. 初始缓冲区建议直接按 `payload_limit + 1` 分配，省掉
   `780→…→80000` 的 7 次 realloc；解压路径本来就要付出 32 KiB 窗口成本，
   多分配一次 40 KB 的代价可以忽略，上限也更好推理。

### 4.2 零输出的判定

```c
else if(status == Z_BUF_ERROR) {
    if(strm->avail_in != 0) {
        /* 输入还有剩余但 inflate 无法继续：真错误（见 4.3 第 2 条） */
        ... error
    }
    if((out_maxlen - strm->avail_out) == 0) {
        /* 输入已全部消费且没有产生输出。这是**合法**的：
         *  - Z_SYNC_FLUSH 在无新数据时产生的空块；
         *  - 只含 zlib 头的报文（跨报文流的第一个包）。
         * 应返回 0 并让 transport.c:341 的
         * fullpacket_payload_len < 1 去判 PROTO。 */
        *dest = out; *dest_len = 0;
        return 0;
    }
    break;
}
```

把当前的"零输出即报 `ZLIB`"改为"零输出交给 `transport.c:341`"，这样：

- 合法空 flush 块不再被误杀（实测目前返回 `PROTO(-14)`，见 2.6）；
- 零输出报文得到与"payload 太短"一致的 `PROTO`，而不是随实现变化的
  `ZLIB`。

**必须说明**：这修不掉"流被截断"的问题。实测表明 zlib 给出的
`data_type` 与 `inflateSyncPoint()` **都不能可靠区分**"本包正好在 flush
边界结束"与"本包在块中间被切断"：

```
Z_PARTIAL_FLUSH 发送方, A=[0,43)
  boundary feed=43  Z_PARTIAL out=5000 avail_in=0 datatype=0x05 eob=0 eos=0
  truncated feed=42 Z_PARTIAL out=5000 avail_in=0 datatype=0x80 eob=0 eos=1  <-- 反而置了 eos
Z_SYNC_FLUSH 发送方, A=[0,47)
  boundary feed=47  Z_PARTIAL out=5000 avail_in=0 datatype=0x80 eos=1
  truncated feed=46 Z_PARTIAL out=5000 avail_in=0 datatype=0x18 eos=0
```

即 `data_type & 128` 在"被截断 1 字节"时反而为真。压缩层无法单方面解决，
只能在**上层**用报文内嵌长度自洽性来发现（4.6）。因此 4.2 只处理零输出，
不要试图在这里判截断。

### 4.3 明确"跨报文压缩流"的验收规则

RFC 4253 §6.2 的含义是：压缩流在**整个连接方向**上连续，报文边界与
deflate 块边界无关。因此正确做法是**接受任意切分**，但要求：

1. **同一条流**：`remote.comp_abstract` 在 kex 之间保持，不得每包重建
   （现状已经如此，`kex.c:349-354` 只在 NEWKEYS 时重建）；
2. **每次 `inflate` 必须消费完本包全部输入**（`avail_in == 0`），
   否则说明发送方把多余的字节塞进了本包——应拒绝。实测在合法样本中
   `avail_in` 恒为 0（`/tmp/pktlab/phase17.c` 的 A 组，5 组输入全部
   `avail_in=0`），但这个字段值得显式断言，而不是依赖；
3. **`Z_STREAM_END` 只允许出现在 kex 边界**，中途出现即为协议违例；
   现状 `comp.c:266` 会把它当普通错误报 `ZLIB`，语义不清；
4. **跨报文的"输出截断"必须在 `packet.c` 侧兜底**：既然边界与块边界
   无关，就必须假设任何一个报文都可能只解出半条 SSH 消息，
   靠 4.6 的内嵌长度校验发现。

建议把这四条写进 `docs/`（例如 `docs/compression.md`），并做成回归用例。

### 4.4 出错即失效，不要留下"半死"会话

```c
/* transport.c，decomp 失败分支 */
if(rc) {
    /* zlib 流已不可恢复：标记会话不可用，避免上层无限重试 */
    session->socket_state = SSH2_SOCKET_DISCONNECTED;
    return rc;
}
```

同时 `session.c` 的 poll 循环应当传播错误：

```c
int r;
/* 现状：while(ssh2_transport_read(...) > 0);  —— 错误被吞 */
while((r = ssh2_transport_read(fds[i].fd.channel->session)) > 0)
    ;
if(r < 0 && r != LIBSSH2_ERROR_EAGAIN) {
    /* 解压/解密类错误不可恢复：标记会话断开，让后续调用立即失败，
     * 并让 poll 把该 fd 报为可读，由调用方去取真正的错误码 */
    fds[i].fd.channel->session->socket_state = SSH2_SOCKET_DISCONNECTED;
    fds[i].revents |= LIBSSH2_POLLFD_SESSION_CLOSED;
}
```

（`libssh2_poll` 的返回值语义不好扩展时，至少要把
`socket_state` 置为断开，让后续调用立刻失败而不是反复解压同一个坏流。）

### 4.5 为报文队列加上限

`ssh2_packet_add()` 入队前检查（`session->packets_bytes` 与
`LIBSSH2_PACKET_MAXQUEUE` 均为**新增**字段/常量，当前代码里没有）：

```c
/* 允许的未读字节数应绑定到该方向窗口，而不是拍一个常数 */
if(datalen > LIBSSH2_PACKET_MAXQUEUE - session->packets_bytes)
    return ssh2_err(session, LIBSSH2_ERROR_OUT_OF_BOUNDARY,
                    "incoming packet queue full");
session->packets_bytes += datalen;
```

计数器在 `channel.c` 消费报文处（`SSH2_FREE(session, readpkt->data)` 位于 `channel.c:2045`，以及 `ssh2_channel_close()` 清队列时的 `channel.c:2643-2647`）与 `session_free()` 里
相应扣减。注意用减法而不是加法比较，避免 `packets_bytes + datalen`
溢出（与 `comp.c:112-114` 的写法保持一致）。

可选的具体值：

- 复用 `LIBSSH2_CHANNEL_WINDOW_DEFAULT`（2 MiB）作为全局上限，
  与现有流控模型一致；
- 或按 channel 分别预算，未读字节数已由 `channel->read_avail` /
  `remote.window_size` 跟踪，brigade 上"不属于任何 channel 的报文"
  另设小上限（例如 1 MiB + 256 个）。

这样 244x（或字典预热下 561x）的放大就被硬性钉死在
"上限 × 放大倍数"以内。

### 4.6 校验报文内嵌长度（截断后伪合法报文）

`packet.c` 的 `CHANNEL_DATA` / `CHANNEL_EXTENDED_DATA` 分支应在使用前
比对：

```c
/* data_head 之后声明的 string 长度必须与实际剩余字节严格相等 */
if(datalen - data_head < 4 ||
   ssh2_ntohu32(data + data_head - 4) != datalen - data_head) {
    SSH2_FREE(session, data);
    session->packAdd_state = ssh2_nb_state_idle;
    return ssh2_err(session, LIBSSH2_ERROR_PROTO,
                    "channel data length mismatch");
}
```

同类检查应加到所有带 `string` 字段的报文（`CHANNEL_REQUEST`、
`GLOBAL_REQUEST`、`EXT_INFO` 等）。这可以顺带把 4.3 第 4 条
落成强制约束，而不是依赖压缩层"碰巧"断在块边界。

### 4.7 复用性

- `comp_method_zlib_init()` 的 `deflateInit2(... Z_HUFFMAN_ONLY)` 是本端
  压缩策略，与被解码方向无关；不需改动。
- 建议把 `LIBSSH2_PACKET_MAXCOMP`（目前**完全未被使用**，只在
  `include/libssh2.h:196` 定义）删掉或接入发送侧；现在它给人的
  印象是"发送方向有独立上限"，实际没有。

---

## 5. 建议的回归用例（可直接落地到 `tests/`）

`tests/` 目前没有任何压缩相关用例（`grep -rn "compression" tests/` 只命中
一条注释）。建议新增一个用桩 socket 驱动的单元测试：

1. `maxdecomp` 边界：`limit`、`limit+1`、`2*limit-1`、`2*limit`
   四个载荷，断言"接受且 `data_len <= limit`"或"拒绝且会话失效"；
2. 阶梯回归：同一解压长度、不同压缩长度（`src<10000` 与 `src>=10000`
   两档），断言判决一致，杜绝非单调；
3. 零输出：合法空 `Z_SYNC_FLUSH` 块必须成功（`data_len == 0`）；
4. 截断：把一条合法流切在块内部，断言按 4.6 被拒；
5. 错误恢复：`Z_DATA_ERROR` 后断言 `socket_state == DISCONNECTED`，
   而不是"继续返回同一个 `-29`"；
6. 队列上限：持续灌入解压后 40000 字节的未知类型报文，断言堆增长
   被队列上限截断。

---

## 6. 合法基线与可复现性

### 6.1 本机 OpenSSH 合法对照

`/tmp/pktlab/sshd/` 起了一个用户态 `sshd`（端口 2222，ed25519，
`Compression yes`），用 libssh2 自身的公开 API 连接：

```
session_flag(COMPRESS)=0                /* 成功置位 */
Key Ex: Agreed on COMP_CS method: zlib@openssh.com
Key Ex: Agreed on COMP_SC method: zlib@openssh.com
handshake rc=0
userauth_publickey_fromfile rc=0
channel_read total=90014 bytes
expected=90014 actual=90014 MATCH
```

90 KB 输出在压缩流上分多个报文传输、逐包解压、内容与长度完全一致，
证明**合法跨报文压缩流在当前实现下是正确的**；问题只在
"超限/截断/出错"这些边界上。

### 6.2 复现方式

```bash
# 构建（静态库 + zlib + 调试日志）
cmake -S . -B build -DENABLE_ZLIB_COMPRESSION=ON -DBUILD_TESTING=OFF
cmake --build build -j

# 每个探针都只链接真实库，不需要网络：
gcc -g -O0 -DHAVE_CONFIG_H -DLIBSSH2DEBUG -DLIBSSH2_HAVE_ZLIB \
    -DLIBSSH2_OPENSSL -Isrc -Iinclude -Ibuild/src \
    /tmp/pktlab/final.c build/src/libssh2.a -lssl -lcrypto -lz -o final
./final
```

`/tmp/pktlab/` 下的脚本清单：

| 文件 | 用途 |
|------|------|
| `harness.c` | 16 个端到端用例（单包/多包/截断/炸弹/恢复） |
| `final.c` | 第 2.1、2.4 节的汇总表 |
| `phase2.c` … `phase17.c` | 上限阶梯、非单调性、队列、字典预热、边界信号 |
| `truncated.c` | 2.5 节的截断交付 |
| `boundary.c` / `detector.c` | 边界/截断检测信号实验 |
| `dict.c` | 字典预热放大 |
| `ceiling.c` / `fixcheck.c` | 上限阶梯复刻 / 修复方案对拍 |
| `lencheck.c` | 内嵌长度校验能否识别截断 |
| `pollstuck.c` | `libssh2_poll()` 吞错实测 |
| `realclient.c` | 对真实 sshd 的合法基线 |

所有脚本都以 `-fsanitize=address,undefined` 再跑过一遍，结论不变。

---

## 7. 未覆盖 / 需进一步确认

- **加密路径**：本文所有构造都走"未加密帧 + 压缩"，因为 `zlib` 在
  `use_in_auth=1` 时认证前即生效。真实部署多为 `zlib@openssh.com`
  （认证后才启用），此时攻击者需要先通过认证——**除非**服务器被攻陷
  或本身是恶意的，这与任务描述的前提一致。加密只影响 L2 封装，
  不影响 `comp.c`/`packet.c` 的长度与状态逻辑。
- **发送方向**：`ssh2_transport_send()`（`transport.c:1090-1122`）在
  压缩后直接写 `outbuf`，由 `comp()` 保证不越界；`comp_method_zlib_comp`
  在 `avail_out == 0` 时返回错误（`comp.c:185-193`）。未发现独立问题，
  但 `dest_len` 初值为 `MAX_SSH_PACKET_LEN - 5 - 256 = 34739`，
  与 40000 的接收上限不对称，属于设计上的冗余，不是缺陷。
- **`LIBSSH2_PACKET_MAXCOMP`** 完全未使用（见 4.7）。
- 本文未对 `libssh2_channel_flush()` 的窗口返还路径做压力测试；
  该路径会 `SSH2_FREE` 已入队报文，可能部分缓解 2.4，但不构成上限。
