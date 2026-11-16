# SSH 协商 zlib 后入站压缩流的长度、内存与错误传播分析

- 目标代码：`src/comp.c`、`src/transport.c`、`src/packet.c`、`src/kex.c`、`src/session.c`、`include/libssh2.h`
- 分支：`task/72`（工作树干净）
- 结论摘要：**存在 1 个高危问题**（解压错误后复用脏 zlib 状态：未消费输入被丢弃、解码错位，可组装出攻击者指定类型的"合法"报文如 `USERAUTH_SUCCESS`，且错误不断开连接），**另有 3 个中危**（解压上限实际约为文档值的 2 倍、截断流被当作完整报文接受、压缩报文队列无上限导致内存放大）和 2 个低危（零输出帧触发错误、错误不记录）。未发现内存泄漏。

---

## 1. 方法

本机没有 `cmake`/`autotools`，因此直接用 `gcc` 编译仓库源码为静态库，再用一个"离线传输层"harness 驱动**真实的** `ssh2_transport_read()` 与 `comp_method_zlib_decomp()`：

- 配置头手工生成于 `/tmp/ssh2build/inc/libssh2_config.h`（`LIBSSH2_OPENSSL`、`LIBSSH2_HAVE_ZLIB`、常用 `HAVE_*`）。
- 所有 `src/*.c` 以 `-fPIC -DHAVE_CONFIG_H` 编译成 `libssh2.a`。
- harness 用 `libssh2_session_init_ex()` 自定义分配器（统计 `live/peak` 字节），把 `recv_cb` 换成由内存缓冲区喂数据，然后按 RFC 4253 §6 的线格式手工拼出**明文**（未加密、无 MAC）入站报文，逐包调用 `ssh2_transport_read()`。
- 压缩端用 zlib `deflateInit(...,9)` + `Z_SYNC_FLUSH` 模拟"合规服务端"；并单独用 `deflateInit2(Z_BEST_SPEED, Z_DEFLATED, 15, 8, Z_HUFFMAN_ONLY)` + `Z_PARTIAL_FLUSH` 复刻 libssh2 自己的发送端（`src/comp.c:145-146`、`src/comp.c:183`），用于互操作基线。

harness 源文件：`/tmp/ssh2build/h2.c` … `h20.c`（脚本与样本分离，未写入仓库）。

**局限**：未跑完整握手，未覆盖加密/MAC/EtM 组合；但本次分析的目标（解压 → 长度校验 → 报文交付）全部在明文路径上，且相关代码不依赖加密状态。所有数字均为本机实测。

---

## 2. 代码路径：从解压到报文交付

### 2.1 上限常量

| 常量 | 值 | 位置 |
|---|---|---|
| `MAX_SSH_PACKET_LEN` | 35000 | `src/libssh2_priv.h:219` |
| `PACKETBUFSIZE` | 35000 | `src/libssh2_priv.h:612` |
| `LIBSSH2_PACKET_MAXPAYLOAD` | 40000 | `include/libssh2.h:204` |
| `LIBSSH2_PACKET_MAXDECOMP` | 40000 | `include/libssh2.h:200` |
| `LIBSSH2_PACKET_MAXCOMP` | 32000 | `include/libssh2.h:196`（发送端） |

注意：RFC 4253 §6.1 要求实现必须能处理**未压缩载荷 ≤ 32768、整包 ≤ 35000**。`MAXDECOMP` 已经比 32768 高，但注释自称"plays it safe"。

### 2.2 入站读取与长度校验

`ssh2_transport_read()`（`src/transport.c:397`）在收到首个块后解析 `packet_length` 并校验：

- `src/transport.c:624-627`、`636-641`、`670-674`：`packet_length < 1` → `LIBSSH2_ERROR_DECRYPT`；`> LIBSSH2_PACKET_MAXPAYLOAD` → `LIBSSH2_ERROR_OUT_OF_BOUNDARY`。
- `src/transport.c:696-697`：`total_num > LIBSSH2_PACKET_MAXPAYLOAD` → `OUT_OF_BOUNDARY`。
- `src/transport.c:701`：`p->payload = SSH2_ALLOC(session, total_num)`——**分配量受 40000 上限约束，这里是正确的**。

也就是说：**线缆上的压缩字节数被限制在 40000 以内**（实测 `packet_length=40001` 直接被 `-41` 拒绝，零分配）。

### 2.3 解压

整包到齐后进入 `transport_fullpacket()`（`src/transport.c:189`）：

```c
312  compressed = session->remote.comp && session->remote.comp->compress &&
313      ((session->state & SSH2_STATE_AUTHENTICATED) ||
314       session->remote.comp->use_in_auth);
317  if(compressed && session->remote.comp_abstract) {
326      rc = session->remote.comp->decomp(session, &data, &data_len,
328                                     LIBSSH2_PACKET_MAXDECOMP,   /* 40000 */
329                                     p->payload,
330                                     session->fullpacket_payload_len,
331                                     &session->remote.comp_abstract);
332      SSH2_SAFEFREE(session, p->payload);
333      if(rc) return rc;
337      session->fullpacket_payload_len = data_len;
338  }
341  if(session->fullpacket_payload_len < 1) { ... return LIBSSH2_ERROR_PROTO; }
346  session->fullpacket_packet_type = p->payload[0];
355  rc = ssh2_packet_add(session, p->payload, session->fullpacket_payload_len, ...);
```

### 2.4 解压器本体

`comp_method_zlib_decomp()`（`src/comp.c:199-299`）：

```c
212  if(src_len <= SIZE_MAX / 4)
213      out_maxlen = (uInt)src_len * 4;
215      out_maxlen = payload_limit;
223  if(out_maxlen < 25) out_maxlen = 25;
226  if(out_maxlen > payload_limit) out_maxlen = payload_limit;   /* 仅初始化时钳位 */
231  strm->next_out = SSH2_ALLOC(session, (uInt)out_maxlen);
239  for(;;) {
244      status = inflate(strm, Z_PARTIAL_FLUSH);
246      if(status == Z_OK) {
247          if(strm->avail_out > 0) break;        /* 任意前缀都当作"完成" */
252      else if(status == Z_BUF_ERROR) {
255          if((out_maxlen - strm->avail_out) == 0) { free; return ZLIB; }
264          break;                                /* 输入耗尽也当作"完成" */
266      else { free; return ZLIB; }
275      if(out_maxlen > payload_limit || out_maxlen > SIZE_MAX / 2) {
276          SSH2_FREE(session, out);
277          return ssh2_err(session, LIBSSH2_ERROR_ZLIB,
278                          "Excessive growth in decompression phase");
279      }
283      out_maxlen *= 2;                          /* 可翻到 2×payload_limit */
284      newout = SSH2_REALLOC(session, out, out_maxlen);
291      strm->next_out = (Bytef *)out + out_ofs;
292      strm->avail_out = (uInt)(out_maxlen - out_ofs);
293  }
296  *dest_len = out_maxlen - strm->avail_out;
```

关键结构性问题有三处：

1. **上限检查与倍增不同步**：`275` 行的检查发生在倍增**之前**，且判据是 `out_maxlen > payload_limit`（严格大于）。因此 `out_maxlen` 可以合法地变成 `40000`，随后 `283` 倍增为 `80000`，而 `80000 > 40000` 才在**下一轮**报错。净效果是**单包最大缓冲可达 2 × `MAXDECOMP` = 80000**。
2. **两处"当作完成"的分支都不验证报文边界**：`246-251`（`Z_OK` 且还有剩余空间）和 `252-264`（`Z_BUF_ERROR` 且已产出 >0 字节）都直接 `break`，把"解压器还需要更多输入"的**截断流**当成完整载荷返回。
3. **错误路径不解压器复位**：`266-273` 与 `275-279` 只 `free` 输出缓冲，**不** `inflateReset()` / 不置错标志。`strm` 保持 mid-block 状态，且该段**还有 5988 字节压缩输入未消费**；而 `229-230` 每次调用都会把 `avail_in` 覆盖成新段的长度——上一段未消费的压缩字节被**静默丢弃**，解码器从此错位。全仓库没有任何 `inflateReset` 调用（`grep -rn "inflateReset" src/` 为空），解压器只在 KEX（`src/kex.c:337-356`）和会话销毁（`src/session.c:896-908`）时 `dtor`/`init`。

### 2.5 交付

`ssh2_packet_add()`（`src/packet.c:618`）只以 `data[0]` 取消息类型，**不再校验 `datalen` 是否超过 32768/35000**；未内联处理的消息（如 `SSH_MSG_USERAUTH_BANNER=53`）被 `ssh2_list_add(&session->packets, ...)`（`src/packet.c:1344`）**无上限**地挂入队列。队列唯一的消费点在上层 API 取包时。

---

## 3. 实测结果

### 3.1 解压上限实际约为文档值的 2 倍

"平坦输出"指服务端压缩前的原始载荷长度；`wire` 指线缆上的压缩字节数；`q_alloc` 是最终挂入队列的缓冲容量；`peak_delta` 是本包在传输层新增的堆峰值（不含 zlib 常驻 ~32 KB 窗口）。

**可压缩串（0/1 噪声，约 8:1），已预热 zlib 窗口（`h16.c`）：**

| 平坦输出 | wire | delivered | q_alloc | peak_delta | q_alloc/wire |
|---|---|---|---|---|---|
| 1000 | 201 | 1000 | 1608 | 1815 | 8.0 |
| 10000 | 1624 | 10000 | 12992 | 14622 | 8.0 |
| 32768 | 5012 | 32768 | 40096 | 45114 | 8.0 |
| 40000 | 5996 | 40000 | 47968 | 53970 | 8.0 |
| 50000 | 7478 | 50000 | 59824 | 67308 | 8.0 |
| 63277 | 9458 | 63277 | 75664 | 85128 | 8.0 |
| **79999** | 11969 | **79999** | **80000** | 91975 | 6.7 |
| 80000 | — | — | — | — | 被拒 `-29` |

`MAXDECOMP = 40000`，但 **79999 字节被成功解压并交付**（`h6.c` #1、`h16.c` 一致）。直接调用解压器的边界（`h6.c`）：

```
flat=79999 wire=12515 direct: rc=0  outlen=79999 alloc=80000
flat=80000 wire=12501 direct: rc=-29 outlen=0    alloc=0
```

**高压缩比串（全 0，约 635–685×），经真实传输层（`h17.c`）：**

| 平坦输出 | wire | delivered | q_alloc | peak_delta | 放大倍数 |
|---|---|---|---|---|---|
| 40000 | 63 | 40000 | 64512 | 97349 | **635×** |
| 50000 | 73 | 50000 | 74752 | 107599 | **685×** |
| 60000 | 83 | 0 | 0 | 75353 | 被拒 `-29` |
| 80000 | 102 | 0 | 0 | 85100 | 被拒 `-29` |

注意"被拒"并不代表安全：它只是说明该特定 `wire` 长度对应的倍增台阶（如 0/0 串 `wire=83` → `4×83=332`，倍增序列 `332→…→47104`，止于 47104 < 60000）没够到输出长度。换个 `wire` 就行——`h18.c` 用 `wire=73` 拿到 50000 字节交付（685×）；噪声串 `wire=11969` 可拿到 79999（6.7×）。**上限是 `wire` 的锯齿函数，落在 40000–80000 之间，并非 40000。**

### 3.2 每包内存与队列放大

传输层对**单个**已接受报文的峰值新增堆分配为 `q_alloc + zlib 递归缓冲`，实测 91975–112768 字节/包（`h16.c`、`h6.c`）。而 `session->packets` 队列**没有任何条数或字节上限**（`grep` 确认无 `max/limit`）。若应用未及时取包（或对 `SSH_MSG_USERAUTH_BANNER` 等异步类型不取包），内存单调增长（`h19.c`，200 个全 0 段）：

```
prepared 200 segments, wire=14.8 KB
baseline live=90216
after pkt0   rc=53  queued_payload=50000    live=197784
after pkt1   rc=53  queued_payload=100000   live=271560
after pkt199 rc=53  queued_payload=10000000 live=14879208
FINAL: 200 packets queued, payload=10000000 bytes, live=14879208, peak=14879238,
       wire=14.8KB -> heap/wire=978.8x
```

**14.8 KB 网络输入 → 约 14.9 MB 常驻堆（≈979×）**，且 `live` 直到 `libssh2_session_free()` 才归零。这正是题目所述"报文长度上限与解压缓冲增长不同步会放大内存占用"的可利用形态：上限只管住了**线上压缩后**的 40000，却没管住**解压后**的实际交付量与**队列积压量**。

### 3.3 截断流被当作完整报文接受

把服务端一段完整压缩流在中途截断后作为独立 SSH 报文交付（`h6.c` #4、`h4.c` P3）：

```
sent=2000 wire=296 cut=148 -> rc=53 delivered=138 (accepted as full packet: YES)
sent=1000 wire=26  cut=4   -> rc=53 delivered=1
sent=1000 wire=26  cut=20  -> rc=53 delivered=782
intact                     -> rc=53 delivered=1000
```

`Z_OK && avail_out>0` 与 `Z_BUF_ERROR` 两个分支都把"解压器缺输入"当作"本包结束"。`delivered` 是截断处已产出的任意前缀，被当成**一个合法报文**送入 `ssh2_packet_add()`。由于 SSH 消息本身没有内部长度/校验，一个以 `data[0]` 为 `SSH_MSG_*` 的前缀就是一个"伪有效报文"。

更糟的是**下一包会被污染**（`h6.c` #4）：

```
truncated segment 148/296 -> rc=53 delivered=138 (accepted as full packet: YES)
next legitimate segment (280 wire, sender meant 500) -> rc=194 delivered=138 CORRUPTED
reference intact: seg1 rc=53 delivered=2000
reference intact: seg2 rc=53 delivered=2000
```

截断后解压器停在 mid-block，下一段正常压缩数据被当作**同一 Huffman 块的后续**解码，长度与内容都不再对应发送端。这直接破坏"合法跨报文压缩流"的语义。

### 3.4 解压错误后的脏状态复用（高危）

`transport_fullpacket()` 在 `333` 行 `if(rc) return rc;` 时，`p->payload` 已 `SAFEFREE`，`ssh2_transport_read()` 在 `913` 行把 `p->total_num = 0` 复位——**传输层状态是干净的**，泄漏检查也为 0（`h13.c`：`live bytes after free=0`）。但 **zlib 流没有复位**。

在一个 120000 字节的"炸弹"段上触发 `Excessive growth` 后，紧接着让服务端发送一段**正常的 500 字节消息**（同一压缩流，合规行为），实测（`h13.c`）：

```
bomb wire=18511 expected_out=120001
after bomb:
  rc=-29 err=-29 msg="Excessive growth in decompression phase"
  inflate: avail_in=5988 total_out=80000 msg=0 data_type=7
  transport: total_num=0 payload=(nil) fullpacket_state=0
reading the next legitimate segment (peer sent 500 bytes):
  rc=-13 err=-13 sock=-1
  inflate: avail_in=0 total_out=81853
  synthetic packet type from stale state = 1
```

`total_out` 从 80000 涨到 81853：解压器并未复位，而是**停在炸弹段明文偏移 80000 处**；`229-230` 行又把 `avail_in` 覆盖为下一段的长度，于是新段字节被当成炸弹比特流的"续输入"继续解码。本次调用**新解出 1853 字节**（`81853-80000`，`*dest_len` 只计本轮产出，被丢弃的 80000 字节不会重现），但这 1853 字节是错位解码的产物，**与发送端在本段发送的内容无关**。`data_type=7` 表示仍停在块中间，解压循环却仍以 `Z_OK` 提前 `break`，把它们当作新载荷交付。`type = 1`（`SSH_MSG_DISCONNECT`）就是这样被组装出来的，导致 `sock=-1`。

关键机制：**解码恢复点恰好是炸弹明文的偏移 80000**，因此攻击者在该偏移放置的字节会成为下一个交付报文的首字节（实测 `h21.c`：`bomb total_out=80000` → `next: rc=52 ... QUEUED type=52 len=1770`）。解码恢复点由服务端控制，恢复出的内容与发送端语义无关。

攻击者可以直接**指定**这个合成报文的类型，只要在炸弹明文的输出偏移 80000 处放置目标字节（`h14.c`）：

```
--- attacker wants synthesised message type 52 ---
  bomb read : rc=-29 msg="Excessive growth in decompression phase"
  next read : rc=52 err=-29 sock=0
  SYNTHESISED PACKET QUEUED: type=52 len=1861 first: 34 01 00 01 01 00 01 00 00 00
    -> matches wanted type: YES
```

（`h21.c` 用同样构造复现：`bomb total_out=80000` → `next: rc=52 ... QUEUED type=52 len=1770 alloc=2240`。两次 `len` 不同是因为噪声炸弹的具体内容不同，恢复点之后能被解出的字节数随之变化。）

`52 = SSH_MSG_USERAUTH_SUCCESS`，内容也由攻击者控制（`len=1861`）。

**触发前提与升级路径。** 该利用需要一个已被忽略的解压错误：`transport_fullpacket()` 返回 `-29` 后，`src/transport.c` **没有**把 `session->socket_state` 置为 `SSH2_SOCKET_DISCONNECTED`，也没有让后续读包失效（`h12.c` D2：多次 `-29` 后 `socket_state` 仍为 0；`h13.c`/`h14.c` 第二次 `transport_read()` 即产出合成包）。于是**应用在解压报错后继续使用同一会话**（例如重试另一认证方式、或在 `poll` 循环中再次读包）就会读到合成报文。这不是纯理论路径：

- `comp_method_zlib`（普通 `"zlib"`）的 `use_in_auth = 1`（`src/comp.c:324`），因此**认证阶段解压是开启的**；
- 客户端认证逻辑按 `SSH_MSG_USERAUTH_SUCCESS` 判定成功（如 `src/userauth.c:200`、`src/userauth.c:397`）；
- 因此"炸弹 → 应用重试认证 → 合成 `52`"可让客户端误认为**认证成功**。

若想走到这一步，攻击者只需先协商普通 `zlib`（而非 `zlib@openssh.com`），并在认证阶段发送炸弹。把该路径记为高危的理由是：错误处理把"应当终止连接"的错误降级为"可重试的普通错误"，而 zlib 上下文又未复位，两者叠加产生了协议层伪造能力。若应用在 `-29` 后严格终止会话，则该利用被切断——这正是 R1 要求"错误即断开"的原因。

补充：这不是"每次都需要重新触发"。一旦进入 `Z_DATA_ERROR`，`inflate` 内部 `msg` 状态被固化，**之后所有合法段永久返回 `-29`**，直到下一次 KEX 重建压缩上下文（`src/kex.c:337-356`），而 KEX 时机由服务端掌握（`h12.c` D2）：

```
corrupt  : rc=-29 err=-29
valid #0 : rc=-29 err=-29 inflate.msg=139017086218567 data_type=16
valid #1 : rc=-29 err=-29 inflate.msg=139017086218567 data_type=16
valid #2 : rc=-29 err=-29 inflate.msg=139017086218567 data_type=16
socket_state=0 (0 = still CONNECTED; no disconnect issued)
```

### 3.5 零输出 / 空载荷 / 尾部垃圾

`h6.c` #5、`h12.c` R4：

| 输入 | 返回 | `err_code` | socket_state |
|---|---|---|---|
| 合法空 `Z_SYNC_FLUSH` 帧（7 字节） | `-14` (`PROTO`) | **0**（未记录） | 0（连接） |
| 零字节压缩载荷（`packet_length` 合法） | `-29` (`ZLIB`) | `-29` | 0（连接） |
| 坏 zlib 头（64 字节） | `-29` (`ZLIB`) | `-29` | 0（连接） |
| 200 字节明文 + 16 字节垃圾 | `53`，`delivered=215` | 0 | 0 |

两点问题：
- 一个**完全合法**的"空刷新帧"（合规服务端在无新数据时可能发送）会触发 `fullpacket_payload_len < 1` → `-14`，且 `err_code` 保持 0，`libssh2_session_last_error()` 看不到错误。7 字节即可让客户端读取路径报错。
- 在完整刷新点之后附加 16 字节垃圾，被解压器继续当作新 deflate 块解码，**多出 15 字节被并入载荷交付**（`delivered=215`）。压缩流的"尾部"没有被校验。

### 3.6 合法跨报文压缩流（基线，工作正常）

必须保留的可接受行为（否则修复会破坏互操作）：

- 标准 `Z_SYNC_FLUSH` 分段，6 段 × 600 字节（`h6.c` #7）：`total=3600 expected=3600 -> EXACT`。
- **libssh2 自己的发送端**（`Z_HUFFMAN_ONLY` + `Z_PARTIAL_FLUSH`，`src/comp.c:145-146,183`）6 段 × 700 字节（`h12.c` D3）：接收端每段 `delivered=700 OK`。
- 一个压缩段内包含多条 SSH 消息（`h15.c`）：4 × 100 字节 → **合并为一个 `len=400` 的报文**交付，不做 SSH 消息分帧。

这三条是验收修复的回归基线。

---

## 4. 问题清单

| # | 级别 | 问题 | 证据 |
|---|---|---|---|
| P1 | **高** | 解压错误后复用脏 zlib 状态：未消费的压缩输入被静默丢弃，解码错位，组装成攻击者指定类型的报文（可为 `USERAUTH_SUCCESS`）；且错误不断开连接 | `h13.c`、`h14.c`；`src/comp.c:266-279`（不复位）、`src/comp.c:229-230`（覆盖 `avail_in`）、`src/transport.c:333`（不断开） |
| P2 | 中 | 解压上限实际为文档值的 ~2 倍（最高 79999 交付 / 80000 分配），且随 `wire` 呈锯齿变化 | `h6.c`、`h16.c`、`h17.c`、`h18.c`；`src/comp.c:226-227`、`275-283` |
| P3 | 中 | 截断压缩流被当作完整报文接受（"截断后伪有效报文"），并污染下一包 | `h6.c` #4、`h4.c` P3；`src/comp.c:246-264` |
| P4 | 中 | 解压后报文队列无上限；14.8 KB 输入可常驻 ~14.9 MB 堆（≈979×） | `h19.c`；`src/packet.c:1329-1346`（无 cap） |
| P5 | 低 | 合法空刷新帧触发 `-14`；错误未被 `err_code` 记录 | `h6.c` #5；`src/transport.c:341-344` |
| P6 | 低 | 解压错误不断开会话，`Z_DATA_ERROR` 后永久失效直至服务端主导的 KEX | `h12.c` D2；`src/transport.c:333`、`src/kex.c:337-356` |
| — | 信息 | 未发现内存泄漏：所有错误路径均释放输出缓冲与 `p->payload`（实测 free 后 `live=0`） | `h13.c`、`h16.c` |

**是否存在"超上限分配"？** 存在，但形式是"上限本身失效"而非整数溢出：`out_maxlen` 可增长到 `2 × MAXDECOMP = 80000`（P2），而 `comp_method_zlib_alloc()`（`src/comp.c:108-117`）的乘法溢出防护是有效的，未发现 wrap。**是否存在"截断后伪有效报文"？** 存在（P3），且与 P1 组合后可升级为伪造认证报文。**是否存在"错误后复用脏状态"？** 存在且可被主动利用（P1）。

---

## 5. 合法跨报文压缩流应如何验收

zlib 在 SSH 中的正确模型（RFC 4253 §6.2）：压缩上下文在**整个密钥周期内连续**，每个 SSH 报文的明文被送入同一个 deflate 流并刷新，接收端必须把**恰好一个报文**的压缩数据解出并交付。因此"接受/拒绝"的正确判据不是"zlib 返回了 `Z_OK`"，而是下面四条**同时**成立：

1. **输出长度 ≤ 单包硬上限**。上限应取 RFC 的 32768（或至多 `MAX_SSH_PACKET_LEN` 35000），**并且在每次 realloc 之前**用"翻倍后的值"比较，使缓冲永远不超过上限。绝不能出现 `2 × limit` 的台阶。
2. **输入恰好耗尽**：解压结束时 `strm->avail_in == 0`。这能抓出"本段剩余未消费压缩字节"，但**不足以**抓出尾部垃圾（实测 `h22.c`：200B + 16B `0xAB` → `avail_in=0`、`delivered=215`，垃圾被当作新 deflate 块解码完毕）。
3. **解压器停在块边界**：以 `inflate(strm, Z_BLOCK)` 循环，要求最终 `strm->data_type & 128`（block end）或 `Z_STREAM_END`。实测该标记能区分本组样本（`h22.c`：完整段 `data_type=128`，尾部垃圾 `69`，半截断 `6`），但**不能完全依赖**——`h10.c` 显示对 `Z_SYNC_FLUSH` 末尾若干字节的截断会被判为 `128`（伪完整）；且 libssh2 自身发送端用 `Z_PARTIAL_FLUSH`，其**完整**段并不以可检测的 flush 点结束。故第 3 条是"尽力检测"。
4. **解压后 `1 ≤ len ≤ 32768`**，且压缩上下文**仅在该包被成功接受后**才允许前进。

> 结论：不存在单一 zlib 侧判据能同时（a）接受 libssh2 自身的 `Z_PARTIAL_FLUSH` 段、（b）拒绝所有截断与尾附垃圾。因此真正可靠的防线是 **R2 的硬输出上限 + R1 的错误即断开 + R4 的队列上限**；边界检测只能降低概率，不能作为唯一判据。

配套的接收端状态机规则：

- 解压返回任何错误（`ZLIB`/`ALLOC`/"excessive growth"）时，必须把 `remote.comp_abstract` 标记为**失效**，并在同一次返回中把会话置为 `SSH2_SOCKET_DISCONNECTED`（或至少拒绝后续所有压缩数据直到成功 KEX）。**禁止**在同一 zlib 对象上继续解压下一段——这就是 P1 的根因。
- 每次进入 `decomp()` 前记录 `avail_in`/`total_out` 基线；返回后若 `total_out` 增量 ≠ 交付长度，判为协议错误。
- 队列必须有上限（条数或字节），并对"未消费仍持续增长"触发断开。

**验收用例（可直接复用本报告的 harness 基线）**：

| 用例 | 期望 |
|---|---|
| 6 × 600B `Z_SYNC_FLUSH` 分段 | 每段 `delivered=600`，总计 3600，字节完全一致，**无错误** |
| libssh2 自身发送端（`Z_HUFFMAN_ONLY`+`Z_PARTIAL_FLUSH`）6 × 700B | 每段 `delivered=700`，**无错误**（不得因边界检测而误拒） |
| 单段内 4 × 100B 消息 | 合并为 `len=400` 的一个报文 |
| 一段 32768B 合法载荷 | `delivered=32768`，分配峰值 ≤ ~32768+常数 |
| 一段 79999B 载荷 | **拒绝**，`delivered=0`，不产生任何报文 |
| 中途截断的段 + 随后一段合法数据 | 第一段**拒绝**（或至少不交付伪报文）；第二段仍能正确解出 500B |
| 炸弹段（触发上限）+ 随后合法段 | 第一个错误即断开；**不得**产生任何 `packet_add`；不得合成类型 1/52 |
| 完整段 + 16B 垃圾 | 拒绝（需 `data_type` 块边界检查；`avail_in` 对此无效） |
| 合法空刷新帧 | 不产生报文，但**不报错**（或按实现约定静默跳过） |
| 200 × 50KB 段不消费 | 队列达到上限即断开，堆不随输入线性增长 |

---

## 6. 修复建议

按优先级：

### R1（对应 P1，必须修）

在 `src/comp.c` 的 `comp_method_zlib_decomp()` 错误分支（`266-279`）执行 `inflateReset(strm)` 或 `inflateEnd()+inflateInit()` 并把 `strm` 置为不可用状态；在 `src/transport.c:333` 的 `if(rc) return rc;` 之前把 `session->socket_state = SSH2_SOCKET_DISCONNECTED`（参照 `src/packet.c:707` 的 strict-KEX 违规处理），并 `ssh2_err()` 记录具体原因。核心约束：**任何一个解压错误之后，绝不能再把下一段数据交给同一个 zlib 流。**

### R2（对应 P2）

把上限判定改为"翻倍后不得越界"：

```c
/* before growing */
if(out_maxlen >= payload_limit || out_maxlen > SIZE_MAX / 2) { ... error ... }
new_maxlen = out_maxlen * 2;
if(new_maxlen > payload_limit) new_maxlen = payload_limit;
```

并把 `LIBSSH2_PACKET_MAXDECOMP` 收到 32768（RFC 要求的最小值），同时把 `src/transport.c:328` 传入的 `payload_limit` 显式绑定到同一常量。

### R3（对应 P3）

校验 `strm->avail_in == 0`（非零即 `LIBSSH2_ERROR_PROTO`），并改用 `inflate(strm, Z_BLOCK)` 检查 `data_type & 128` 以识别"停在块中间"的截断段（实测 `h22.c`：截断 `data_type=6`、尾附垃圾 `69`、完整 `128`）。**注意**：该判据对 `Z_SYNC_FLUSH` 的少量尾部截断会误判（`h10.c`），且与 libssh2 自身 `Z_PARTIAL_FLUSH` 发送端的"完整段"语义冲突，因此应作为**辅助检测**，主防线仍是 R2 的硬上限与 R1 的失败即断开。

### R4（对应 P4）

在 `ssh2_packet_add()`（`src/packet.c:1329` 附近）增加队列条数/字节上限（例如 128 包或 `2 × LIBSSH2_CHANNEL_WINDOW_DEFAULT`），超限返回 `LIBSSH2_ERROR_ALLOC` 并断开；或在 `transport_fullpacket()` 中拒绝 `data_len > 32768` 的压缩解压结果。

### R5（对应 P5/P6）

`src/transport.c:341-344` 的 `fullpacket_payload_len < 1` 分支应区分"合法空刷新帧"（静默跳过，`return 0` 或继续读取）与真正的协议错误，并调用 `ssh2_err()` 记录。解压类错误统一置断开状态，避免 `Z_DATA_ERROR` 后会话悬挂在"connected 但永久 `-29`"的不一致状态。

---

## 7. 结论

- zlib 协商后，入站路径的长度控制只作用于**压缩后**的 40000 字节，解压后的实际交付量可接近 80000，且队列无上限；恶意服务端可用 14.8 KB 输入换取约 14.9 MB 常驻堆（≈979×）。
- 解压器把"`Z_OK` 但还有空间"和"`Z_BUF_ERROR`"都当作包结束，因此**截断流会成为伪有效报文**并污染后续报文；尾部垃圾则被当作新的 deflate 块继续解码并入载荷（`avail_in` 仍为 0，只有块边界标记能察觉）。
- 最严重的是错误路径**不复位 zlib 状态**：解码器停在炸弹明文偏移 80000，后续段的字节被当作续输入错位解码，组装出**攻击者指定类型与内容**的报文（实测在偏移 80000 放置 `52` 即得到 `type=52 len=1770` 的排队报文）。这已超出"放大内存占用"，构成协议层伪造能力。
- 合法的跨报文压缩流本身工作正确（`Z_SYNC_FLUSH` 与 libssh2 自身 `Z_PARTIAL_FLUSH` 发送端均逐字节匹配），修复时应以上述两组基线做回归，并把"任一解压错误即断开"作为不可妥协的约束。
