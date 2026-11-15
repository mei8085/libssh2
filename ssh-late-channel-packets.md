# SSH 通道关闭交错时的迟到报文处置分析（libssh2）

针对问题：SSH 通道本地关闭与对端关闭交错时，迟到的 CHANNEL_DATA / CHANNEL_WINDOW_ADJUST /
CHANNEL_REQUEST 仍携带已关闭的通道号。本文基于对本仓库源码的逐行阅读，以及"本地伪造
服务端 + ASan 插桩客户端"的实测结果，分析通道号的定位、复用与释放后报文处置。

- 代码：`src/channel.c`、`src/packet.c`、`src/transport.c`
- 测试装置：`/tmp/l2test/fake_server.py`（paramiko 伪造服务端，可任意排序发送关闭确认、
  迟到数据、窗口调整、请求）、`/tmp/l2test/late_client.c`（libssh2 客户端，
  全库以 `-fsanitize=address -DLIBSSH2DEBUG` 编译，开启 `libssh2_trace(~0)`）
- 场景脚本：`/tmp/l2test/run.sh`，日志：`/tmp/l2test/{cli,srv,out}_s*.log`

---

## 1. 代码分析：通道号的定位、分配与释放

### 1.1 通道号分配：单调递增，事实不复用

`ssh2_channel_nextid()`（src/channel.c:51-74）：

```c
uint32_t id = session->next_channel;          // 会话级单调计数器
/* 再抬高到现存最大 local.id */
session->next_channel = id + 1;               // 只增不减
```

- `session->next_channel` 全会话只递增（全仓库仅此一处写入，见 channel.c:71），
  所有通道类型（session、forwarded-tcpip 监听队列、x11、auth-agent）共用同一分配器
  （src/packet.c:177/372/532）。
- 注释明确承认：只有"快速开关约 40 亿个通道"导致 32 位回绕后，旧通道的迟到数据才
  "可能被新通道捡到"（channel.c:64-70）。**会话内通道号实际不复用**，这是迟到报文
  不会串入新通道的根本原因。

### 1.2 通道号定位

`ssh2_channel_locate()`（src/channel.c:79-104）：先查 `session->channels`，再查各
listener 的待接受队列。`packet.c` 的 `ssh2_packet_add()` 对各类通道报文均先定位：

| 报文 | 定位失败（已释放/未知号）时的行为 | 位置 |
|---|---|---|
| CHANNEL_DATA / EXTENDED_DATA | 记录错误 `LIBSSH2_ERROR_CHANNEL_UNKNOWN`（"Packet received for unknown channel"），丢弃 | packet.c:944-950 |
| CHANNEL_EOF | 静默忽略（"We may have freed already"） | packet.c:1062-1077 |
| CHANNEL_CLOSE | 静默忽略 | packet.c:1211-1220 |
| CHANNEL_WINDOW_ADJUST | 静默忽略（`if(channelp)` 内才调整） | packet.c:1297-1324 |
| CHANNEL_REQUEST(exit-status/exit-signal) | 找不到通道则不落盘；**但 `want_reply=1` 时仍回 CHANNEL_FAILURE，回显该（死）通道号** | packet.c:1122-1197 |

### 1.3 通道仍存在（已收到对端 CLOSE、本地尚未 free）时的迟到报文

这是交错窗口期的关键路径，`packet.c` 的 DATA 分支**不检查** `remote.close`：

- packet.c:1033：`channelp->remote.eof = 0;` —— **任何迟到 DATA 都会把 EOF 标志清零**
  （"Reset EOF status"）。
- packet.c:1047：`read_avail += ...` —— 迟到数据照常入队、消耗接收窗口。
- WINDOW_ADJUST 分支同样不检查 close，直接 `local.window_size += bytestoadd`
  （packet.c:1309，有 uint32 溢出检查 packet.c:1305）。
- exit-status / exit-signal 照常写入 `channelp->exit_status` / `exit_signal`
  （packet.c:1135-1137, 1163-1184）。

### 1.4 释放路径与待发/待收队列清理

`ssh2_channel_free()`（src/channel.c:2600-2701）：

1. 未关闭且连接正常时先 `ssh2_channel_close()`（EAGAIN 则整体返回 EAGAIN 重试）；
2. **只排空该通道的 CHANNEL_DATA / CHANNEL_EXTENDED_DATA 两类排队报文**
   （channel.c:2641-2647，按 recipient 通道号匹配 `ssh2_packet_ask`）；
3. 从 `session->channels` 摘链，清理 `session` 中所有回指该通道的状态指针
   （`open_channel`、`packAdd_channelp`、`scpSend/scpRecv_channel` 等，
   channel.c:2667-2696）——这一组清理是防 UAF 的关键，目前覆盖完整；
4. `SSH2_FREE(session, channel)`。

注意： brigade（`session->packets`）中**其他类型**的报文（如 CHANNEL_SUCCESS/
FAILURE、重复的 CLOSE 等）若引用已释放通道号，free 不清除；它们只能靠后续
`packet_require` 按号匹配消费——而通道号不复用，意味着**永远无人消费**（见 §3 场景 s7）。

### 1.5 读路径的 EOF/关闭判定

- `ssh2_channel_read()`（channel.c:1923-2072）：先把 brigade 中属于本通道的数据拷给
  应用；无数据时若 `remote.eof || remote.close` 返回 0（channel.c:2059）。
  排队数据优先于 EOF，因此"CLOSE 之后入队的迟到数据"仍会被后续 read 交付给应用。
- `libssh2_channel_eof()`（channel.c:2359-2393）：若 brigade 中还有本通道数据则
  返回 0（掩盖 EOF），否则返回 `remote.eof` —— 而 `remote.eof` 会被迟到 DATA 复位
  （§1.3），因此 **EOF 状态可来回翻转**。

---

## 2. 测试装置与场景设计

伪造服务端（paramiko）在通道生命周期的不同时点注入三件套（DATA / WINDOW_ADJUST /
REQUEST exit-status），客户端为 ASan+trace 插桩的 libssh2 程序：

| 场景 | 时序（服务端动作 / 客户端动作） |
|---|---|
| s1 | 服务端 DATA→CLOSE→0.05s 后迟到三件套；客户端读→关→free→开 ch2 |
| s2 | 客户端先关（发 EOF+CLOSE）；服务端 1s 后回 CLOSE 再发迟到三件套（关闭交叉） |
| s3 | 服务端 CLOSE；客户端 free **之后** 1s 再发迟到三件套 + want_reply=1 请求 |
| s4 | DATA→EOF→DATA(EOF 后)→CLOSE；客户端分段读观察 EOF 状态 |
| s5 | 客户端阻塞在 `channel_close()` 等待关闭确认期间，服务端先发 DATA 再回 CLOSE |
| s6 | 服务端 CLOSE；客户端看到 EOF 后空闲 0.6s（通道仍存活），迟到三件套此时到达 |
| s7 | 通道释放后，服务端灌 100000 个 CHANNEL_SUCCESS（引用死通道号），测 brigade 残留 |

补充：为让 s2/s5 的服务端报文顺序不被 paramiko 的自动 CLOSE 应答抢先，测试中
替换了 `Transport._channel_handler_table[MSG_CHANNEL_CLOSE]`（这本身也说明：真实
服务端如 OpenSSH 会立即回 CLOSE，交叉窗口天然存在）。

## 3. 实测可观察结果

全部 7 个场景客户端退出码 0，**ASan/LeakSanitizer 无任何报告**。

### s1 / s3：释放后到达 —— 干净丢弃，无 UAF，无串通道

```
[trace] Conn: Freeing channel 0/0 resources
[trace] Conn: Allocated new channel ID#1            <- 新通道 id=1，未复用 0
[trace] Failure Event: -23 - Packet received for unknown channel   <- 迟到 DATA
[trace] Conn: Channel 0 received request type exit-status (wr 1)   <- 迟到 REQUEST
[trace] Socket: Sent 36/36 bytes                    <- 仍向死通道号回了 CHANNEL_FAILURE
[srv] accepted channel #2: client_id=1 (prev=0, reused=False)
[cli] ch2: read 8 bytes: 'CH2-DATA'                 <- ch2 数据干净，无串入
```

- 迟到 DATA：定位失败 → 丢弃（trace 有错误事件）；WINDOW_ADJUST / EOF / CLOSE：
  静默丢弃；REQUEST：不落盘，但 want_reply=1 时**回复了 CHANNEL_FAILURE**。
- 旧通道释放后，free 的队列排空循环（trace 中连续 `Looking for packet of type: 94/95`）
  正常工作；新通道号不复用（0→1），迟到报文不可能串入新通道。

### s2：关闭交叉（客户端先关）—— 正常

客户端 `channel_close()` 阻塞约 1s 等到服务端的 CLOSE 应答后返回 0；随后到达的
迟到三件套按 §1.2 规则丢弃；ch2 干净。

### s4：EOF 后的数据 —— EOF 状态被迟到数据翻转

```
[cli] ch1: read1 'BEFORE-EOF'
[cli] ch1: read2 (after EOF) => 0, eof=1      <- 应用已看到 EOF
[cli] ch1: read3 (data after EOF) => 9 'AFTER-EOF'  <- 又读到数据
[cli] ch1: eof=1                              <- 最终 CLOSE 再次置位
```

### s5：close 等待期间到达的数据 —— 入队后在 free 时被静默丢弃

```
[trace] Conn: Closing channel 0/0                          <- 客户端阻塞等 CLOSE 应答
[trace] Conn: 23 bytes packet_add() for 0/0/0              <- 迟到数据仍被接受入队
[trace] Conn: increasing read_avail by 23 bytes to 23/2097147
[trace] Conn: Freeing channel 0/0 resources                <- free 排空该 23 字节
```

数据被接受、占窗口、随后随 free 丢弃；**未向服务端补发 WINDOW_ADJUST 退款**
（窗口随通道销毁，无害但属于静默丢数据）。

### s6：CLOSE 后、free 前的空闲窗口期 —— 三类迟到报文全部生效

```
[cli] ch1: read => 0 (EOF/closed); eof=1                 <- 应用已看到 EOF
[trace] Conn: 22 bytes packet_add() for 0/0/0            <- CLOSE 后仍接受 DATA
[trace] Conn: Window adjust for channel 0/0, adding 4096 <- CLOSE 后仍调窗口
[trace] Conn: Exit status 42 received for channel 0/0    <- CLOSE 后仍记录退出码
[cli] ch1: post-EOF read => 16                           <- 应用 EOF 之后又读到数据
[cli] ch1: after idle-wait eof=0 exit_status=42          <- EOF 被翻回 0！
```

### s7：未消费报文类型的 brigade 残留 —— 内存随报文数线性增长

```
[cli] RSS after free: 16780 kB
[cli] RSS after ch2 open (flood pumped): 16932 kB
[cli] RSS after ch2 free (flood still queued?): 33388 kB   <- +16.6MB / 10万条
```

10 万个引用死通道号的 CHANNEL_SUCCESS 全部留在 `session->packets` 直到会话销毁
（会话销毁时会正确释放，故 LeakSanitizer 不报警；但**会话存活期间无上限**）。
free 只排 DATA/EXTENDED_DATA（§1.4），而通道号不复用使这些报文永远匹配不到消费者。

---

## 4. 结论

1. **不存在释放后使用（UAF）**。迟到报文经 `ssh2_channel_locate` 定位失败即弃；
   free 完整清理 session 中全部回指指针；7 个交错场景 ASan 全部干净。
2. **不存在迟到数据串入新通道**。本地通道号全会话单调分配、事实不复用（仅 2^32
   回绕的理论残留，代码注释已自知）；监听队列通道共用同一分配器，无跨池碰撞。
3. **存在错误状态残留/协议违规容忍**（兼容性问题为主，安全影响有限但可观测）：
   - a. CLOSE 后、free 前的 DATA 仍入队并会交付应用，且把 `remote.eof` 清零
     （packet.c:1033）→ 应用层可见"EOF 之后又出数据、EOF 标志来回翻转"（s4/s6）；
   - b. CLOSE 后的 WINDOW_ADJUST 仍修改 `local.window_size`（s6）；
   - c. CLOSE 后的 exit-status/exit-signal 仍写入通道状态（s6，exit_status=42）；
   - d. 对死通道号的 want_reply 请求仍回 CHANNEL_FAILURE（s3）——对端栈可能对此
     敏感（实测 paramiko 收到意外 FAILURE 会关闭自己一侧的通道）；
   - e. 未被消费的报文类型（SUCCESS/FAILURE 等）引用死通道号时在 brigade 中永久
     残留，构成会话期无界内存增长向量（s7，10 万条 ≈ 16.6MB）；
   - f. close 等待期间入队的数据在 free 时被静默丢弃且不退窗口（s5）；
   - g. 传输层出错时 `channel_read` 直接返回错误、丢弃 brigade 中已排队数据
     （channel.c:1964-1965，阻塞 socket 下首轮实测可见 26 字节丢失）。

## 5. 修复建议（兼容合法关闭交错）

原则：RFC 4253 §5.3 允许关闭握手期间存在在途数据，**不能简单丢弃 close 后数据**，
否则会在"对端先发数据再发 CLOSE、本地先关"的合法交错下丢数据。建议按"半关闭
语义"收紧而非全面拒收：

1. **DATA/EXTENDED_DATA**：保留"close 后仍入队"（合法交错需要），但
   - 删除 packet.c:1033 的 `channelp->remote.eof = 0;`，或改为仅在
     `!remote.eof && !remote.close` 时接受入队、EOF/CLOSE 后入队但**不复位 EOF**。
     这样数据不丢、EOF 状态不再翻转（修 a）。
   - 可选：`remote.close` 已置位时仍入队但记 trace 降级为 debug，避免日志噪音。
2. **WINDOW_ADJUST**：`remote.close` 已置位时忽略调整（窗口已无消费者），
   保留溢出检查（修 b）。
3. **CHANNEL_REQUEST**：`remote.close` 已置位时不再写 `exit_status/exit_signal`
   （多数服务端在 CLOSE 前发 exit-status，合法交错不受影响）；`want_reply` 的
   FAILURE 应答改为**仅当通道定位成功时**发送（修 c、d）。
4. **brigade 残留**：在 `ssh2_channel_free()` 中把排空范围从 DATA/EXTENDED_DATA
   扩展到按通道号可匹配的所有通道类报文（SUCCESS/FAILURE/REQUEST 等），或为
   `session->packets` 设总量上限并淘汰最老的无人认领报文（修 e）。
5. **free 前窗口退款**：free 排空 DATA 时累计字节数，若连接仍存活且尚未发出
   CLOSE，可补发一个 WINDOW_ADJUST（低优先级，修 f）。

## 6. 可复验安全判据

以下判据均可由本测试装置（或等价物）复验：

1. **内存安全**：s1–s7 全场景在 ASan+LSan 下退出码 0、无任何报告 —— 当前已满足，
   修复后必须保持。
2. **不串通道**：释放通道 A 后以其通道号注入 DATA/ADJUST/REQUEST，随后新建通道 B
   读到的首包必须等于服务端发往 B 的payload（本测试中为 `'CH2-DATA'` 且仅 8 字节），
   B 的 `exit_status` 必须为初始值 0 —— 当前已满足。
3. **EOF 单调性**（修复目标）：一旦 `libssh2_channel_eof()` 返回 1 且 brigade 无本
   通道数据，之后任何迟到报文不得使其回到 0；`read` 返回 0（EOF）之后不得再返回
   正字节数。当前**不满足**（s4/s6 观测到翻转），修复 1 后应满足。
4. **关闭后状态冻结**（修复目标）：`remote.close=1` 之后，`local.window_size`、
   `exit_status`、`exit_signal` 不再变化。当前**不满足**（s6），修复 2、3 后应满足。
5. **不应答死通道**（修复目标）：对定位失败的 CHANNEL_REQUEST（want_reply=1）
   不产生任何出站报文（以服务端收包计数为据）。当前**不满足**（s3 观测到
   CHANNEL_FAILURE），修复 3 后应满足。
6. **brigade 有界**（修复目标）：向死通道号灌 N 条 SUCCESS/FAILURE 后，会话 RSS
   增量应有固定上界（不随 N 线性增长）。当前**不满足**（s7：10 万条 ≈ +16.6MB），
   修复 4 后应满足。
7. **回归兼容**：对真实 OpenSSH 服务端执行 `exec` 短命令（输出与 CLOSE 几乎同时
   到达的合法交错），输出必须完整、退出码正确 —— 修复 1–3 不得破坏此场景。

---

### 附：复现方式

```sh
# 1) 编译 ASan+trace 版 libssh2（本仓库 src/ 下）
cd src && for f in agent bcrypt_pbkdf blowfish chacha cipher-chachapoly comp crypt \
  global hostkey kex knownhost mac misc openssl packet pem poly1305 publickey scp \
  session sftp transport userauth userauth_kbd_packet version keepalive channel; do
  gcc -c -O1 -g -fsanitize=address -fno-omit-frame-pointer -DLIBSSH2DEBUG \
      -DLIBSSH2_OPENSSL -I. -I../include -o /tmp/l2build/$f.o $f.c; done
ar rcs /tmp/l2build/libssh2_asan.a /tmp/l2build/*.o

# 2) 编译客户端并逐场景运行（服务端为 paramiko 伪造端）
gcc -O1 -g -fsanitize=address -I../include -o /tmp/l2test/late_client \
    /tmp/l2test/late_client.c /tmp/l2build/libssh2_asan.a -lssl -lcrypto -lz
for s in s1 s2 s3 s4 s5 s6 s7; do /tmp/l2test/run.sh $s 1250${s#s}; done
```
