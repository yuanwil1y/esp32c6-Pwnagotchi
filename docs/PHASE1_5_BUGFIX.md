# Phase 1.5 - 缺陷修复与回归验收

Review 基线：`2ae26b1c55858671d8981469a8a3dd3f02e76bbb`（= Phase 1 最终验收
a3006e8 + 验收文档）。本阶段只做缺陷修复、回归测试与验收准备，不开始
Phase 2（World Model 仍是下一项目阶段）。Phase 0/1 的历史验收文档与实机
日志原样保留，未回写。

## 0. 结果概览

| # | 缺陷 | 严重度 | 状态 | 证据级别 |
|---|------|--------|------|----------|
| 1 | RX slot 所有权泄漏（rx_state 错误帧不归还 slot） | P1 | 已修复 | 静态确认 + host 自动复现（修复前红/修复后绿） |
| 2 | MISC 零 payload 被按 sig_len 复制 | P1 | 已修复 | 静态确认 + 官方文档核对 + host 自动复现 |
| 3 | 信道表 `01` 走 1..13、hopper 失败处理过激、task 失败 enabled 不回退、目标信道提前生效、停止后回退陈旧信道 | P2 | 已修复 | 静态确认 + 官方文档核对 + host 单测（策略层）+ 实机确认（country 01→1..11、10.1 hops/s、errors=0，见 §10） |
| 4 | captured length / FCS / IE 边界（截断副本含部分 FCS 进 IE walk、尾部 1 字节漏判、截断与坏帧混淆） | P2 | 已修复 | 静态确认 + host 自动复现 |
| 5 | 不完整观察覆盖可靠字段（清 SSID/降级 RSN→OPEN/清 advertised channel） | P2 | 已修复 | 静态确认 + host 自动复现 |
| 6 | AP 统计含义错误（ap_unique 重复增长、UI 称 AP） | P2 | 已修复 | 静态确认 + host 回归护栏 + UI/串口文案修正 |

自动化回归：`tests/host/`，host 上直接编译生产源码
（`ieee80211_parser.c` / `rx_path.c` / `obs_cache.c` / `hopper_policy.c`），
不另写一套测试逻辑；queue/driver 用最小 mock。CI job
`Host regression tests (Phase 1.5)`（plain + ASan/UBSan）与固件构建并行。

## 1. IDF v5.4 官方契约核对（修复依据）

来源：https://docs.espressif.com/projects/esp-idf/en/v5.4/esp32c6/api-reference/network/esp_wifi.html
及 v5.4 头文件原文：

- `esp_wifi_types.h`，`wifi_promiscuous_pkt_type_t` 的 `WIFI_PKT_MISC`：
  "Other type, such as MIMO etc. 'buf' argument is wifi_promiscuous_pkt_t
  **but the payload is zero length**"。→ 缺陷 2 的 whitelist 依据。
- `esp_wifi_types_native.h`，`wifi_pkt_rx_ctrl_t`：
  - `rx_state`："state of the packet. **0: no error; others: error numbers
    which are not public**"。
  - `sig_len`："length of packet **including Frame Check Sequence(FCS)**"，
    12-bit 位域。→ parse length = min(captured, orig-4) 的依据。
- `esp_wifi.h` / `esp_wifi_types_generic.h`：`wifi_country_t.schan`
  （"Start channel of the allowed 2.4GHz Wi-Fi channels"）、`nchan`
  （"Total channel number"，是**个数**不是上界）；**默认 country 为
  `{cc="01", schan=1, nchan=11}`**，即 world-safe 1..11。→ 缺陷 3 的
  country 表依据。
- `esp_err.h`：`ESP_ERR_WIFI_BASE = 0x3000`；`esp_wifi.h`：
  `ESP_ERR_WIFI_NOT_INIT = BASE+1`、`ESP_ERR_WIFI_NOT_STARTED = BASE+2`；
  `esp_wifi_set_channel()` 的错误集为 `ESP_OK / ESP_ERR_WIFI_NOT_INIT /
  ESP_ERR_WIFI_IF / ESP_ERR_INVALID_ARG / ESP_ERR_WIFI_NOT_STARTED`，其中
  只有 `ESP_ERR_INVALID_ARG` 是确定性"该信道无效"，其余按瞬时错误处理。
  → hopper 失败分类的依据（host 侧常量按同一头文件取值镜像）。

## 2. 缺陷 1：RX slot 所有权泄漏（P1）

根因（静态确认，`wifi_sniffer.c` @2ae26b1）：`promiscuous_rx_cb` 先从
free queue 取 slot，再检查 `rx_state != 0`，命中即 `return`，不归还。
每个错误帧泄漏 1 个 slot；24 次后 pool 永久耗尽，之后所有帧按
`rx_dropped` 丢弃，且没有任何计数能解释原因。

修复（commit `97f15b4`）：

- `rx_state` 门禁移到取 slot 之前：错误帧不再触碰 pool。
- 所有权链 `free → callback → rx queue → consumer → release → free` 收敛到
  `rx_path.c` 一个文件；所有放弃路径（pool 空、enqueue 失败）要么不取
  slot，要么归还。
- 计数口径（`rx_path.h` 恒等式）：
  `rx_total = rx_state_errors + rx_misc + rx_dropped_pool + rx_dropped_queue + rx_queued`；
  `rx_queued = rx_processed + queue_current`（静止时）。
  提前返回不再从统计中消失：错误帧进 `rx_state_errors`，MISC/未知类型进
  `rx_misc`，白名单内零 payload 进 `rx_no_payload`（仍是 queued 子集），
  pool 空 / queue 满分别计数。
- 验证：mock 环境逐 slot 跟踪 FREE/QUEUED/INFLIGHT，注入 30 次（>24）错误
  帧后注入正常帧仍可处理；静止时 24 个 slot 全部回到 free pool；运行时
  free+queued+in-flight=24；双归还/外部归还由 mock 报警。修复前该测试红
  （CI run 35904015317），修复后绿。

## 3. 缺陷 2：MISC 零 payload（P1）

根因：callback 对全部类型按 `sig_len` `memcpy(pkt->payload, ...)`。按
v5.4 契约，MISC 的 payload 长度为 0，`sig_len` 对它没有 payload 语义，
读它没有依据（本次环境未观察到 MISC 帧，属防御性修复；若将来关闭
MISC filter 也必须保留防御分支）。

修复（commit `97f15b4`）：

- 适配层只对 MGMT/CTRL/DATA 声称 payload 字节（`payload_len=sig_len`），
  MISC/未知类型传 0。
- `rx_path` 核心内再做一次 whitelist 防御：非 MGMT/CTRL/DATA 一律不读
  payload（对敌意输入 `payload=NULL, payload_len>0` 也不读，host 敌意
  二进制证明：修复前 plain 构建直接段错误/ASan 报越界读，修复后通过）。
- MISC 单独计数（`rx_misc`）并返回，不进队列、不进 parser。

## 4. 缺陷 3：信道表与 hopper 异常状态（P2）

根因（静态确认，`channel_hopper.c` @2ae26b1）：

1. `build_channel_list()` 用国家码**字符串**映射：非 US/CA 一律 1..13，
   默认 `01`（world-safe）也走 13 信道。
2. `set_channel` 任何失败都立即退役该信道，无确定性/瞬时区分，理论上
   可把全部信道退役。
3. `s_stats.enabled = true` 在 `xTaskCreate` 之前设置，task 创建失败时
   enabled 悬挂为 true。
4. `current_channel` 在任务启动前就报告 `s_channels[0]`（未生效先上报）。
5. hopper 停止后 `wifi_sniffer_get_stats()` 回退到启动信道（陈旧值）。

修复（commit `2d51f7f`，策略层在 `hopper_policy.c`）：

- 信道表改由 `esp_wifi_get_country()` 的 `schan/nchan` 生成
  （nchan 是个数，上界 = schan+nchan-1，用 int 宽类型计算并校验，与硬件
  1..14 求交）；查询失败或区间非法时保守回退 1..11。不按语言/地区猜，
  不调 `set_country`，不用 set_channel 成功反推规则。本机驱动默认
  `{01, 1, 11}` → **1..11**。
- 失败分类（按 IDF 错误码）：`ESP_ERR_INVALID_ARG` = 确定性无效 → 退役
  单个信道；`NOT_INIT/NOT_STARTED` = 驱动不可用 → 停止 hopper（不是退役
  全部）；其余 = 瞬时 → 连续 3 次失败后本轮跳过该信道，信道**永不因瞬时
  错误退役**，下一 pass 重试（有界降级，不无限刷日志：每信道 5s 一条）。
- task 创建失败时 enabled 显式回 false；`current_channel` 只在
  set_channel 成功后更新（0 = 尚无成功跳频，显式 unknown）；停止后保留
  最后已知成功信道，不回退启动信道。
- dwell 保持 300 ms 固定。

测试：`hopper_policy` 纯逻辑覆盖 `(1,11)/(1,13)/(6,4)/(3,5)`、非法/溢出
区间（含 nchan=200 溢出守卫）、回退表、错误分类、有界重试/退役/停止
路径与日志节流。task/驱动交互路径属静态审查，实机验证见 §7。

## 5. 缺陷 4：captured length / FCS / IE 边界（P2）

口径定义（commit `97f15b4` + `6575f8e`）：

- `orig_length`：驱动报告的空口长度，**含 4 字节 FCS**（sig_len）。
- `captured_length`（`pkt->length`）：实际复制进 pool 的字节数
  （≤ min(orig,512)）。
- `rx_path_parse_length()` = min(captured, orig-4)（orig>=4 时；宽类型
  计算防下溢），即交给 parser 的 MAC body：完整帧减 FCS；截断副本若只缺
  FCS（如 513→512）取 orig-4，**部分 FCS 字节不进 IE walk**；若截断深处
  MAC body（如 600→512）取 captured。
- `rx_path_body_truncated()`：只有 MAC body 字节缺失（不只是 FCS）才算
  "截断捕获"，parser 才允许把尾部标 incomplete 而不是判坏帧。

parser（commit `6575f8e`）：

- 深层解析前置守卫：protocol version != 0、order 位（HT 变长头）、
  More-Fragments → 保守拒绝深入解析（不套固定偏移误读）。
- IE walk 三态：完整 body 中 IE body 越界 / 尾部残留 1 字节 / SSID 长度
  33 / DS 长度≠1 → `malformed_ie`；capture 截断导致无法判断的尾部 →
  `ie_walk_incomplete`（不自动归因为空口坏帧）；截断捕获即使干净结束也
  不算 complete。
- 关键 IE（SSID、DS Parameter）重复：首个生效，重复置 `dup_critical_ie`
  且 complete=false。
- 全零字节 SSID = 隐藏 SSID 表示（ssid_len=0）；SSID 0 = hidden（beacon）
  / wildcard（probe req）；原始字节不依赖 strlen，仅在输出时 sanitize。
- DS Parameter：长度必须为 1（否则 malformed）；值 1..14 才写入
  `advertised_channel`，其他值不写；`rx_channel` 独立不受影响。

测试覆盖 orig 0..4、复制边界 511/512/513/514 与部分 FCS、零 IE、尾部
1 字节、IE 边界/头/体内截断、SSID 0/32/33/全零/重复、DS len 0/2 与值
0/6/200、深层解析守卫。修复前 CI 红（FCS 字节被判 malformed、尾部字节
漏判、截断被误报），修复后绿。

## 6. 缺陷 5+6：观察合并策略与 AP 统计语义（P2）

缺陷 5 根因：cache 对每个"解析成功"的 beacon 无条件覆盖，截断/畸形副本
可清掉已知 SSID、把 RSN 降级为 OPEN（"没看到 RSN IE"当作 negative
evidence）、把 advertised channel 清零。

修复（commit `7604a61`）：**只有 complete 观察能更新 cache**（策略选择：
保守整体跳过，而非逐字段合并——语义单一、可测）。完整观察才是
authoritative：coarse security（RSN>WPA>PRIVACY>OPEN，presence 级）可升可
降；hidden/missing SSID 不清已知名；DS 无值不清信道；`last_*` UI 上下文
同样只在完整观察且 SSID 非零时刷新。序列 valid→truncated→valid 全程无
降级（测试覆盖）。Phase 2 之前不做 RSN/WPA suite 解析。

缺陷 6 根因：`ap_cache_update` 对新条目或属性变化都返回 true，
`ap_unique` 因此对同一 BSSID 重复增长，缓存淘汰后再见又+1，被 UI/文档
当"total unique AP"展示。

修复（commit `ae58b69`）：不引入 AP DB（留给 Phase 2）。`ap_unique` 删除，
拆为 `ap_cache_inserts / ap_cache_updates / ap_cache_evictions`（cache
变化计数）+ `ap_cache_occupied`（0..32 当前占用）+ `ap_obs_skipped`
（未合并的不完整观察数）。串口 OBS 行改为
`APCACHE occ=%u/32 ins=.. upd=.. evict=.. skip=..`；状态屏 `AP:` 改为
`AP cache:`；README/DEVELOPMENT 同步纠正。淘汰再见 = insert（明确是
cache 变化而非"新 AP"）。日志限流只影响打印，不影响 cache 维护与计数。

## 7. 测试、CI 与构建

- host 回归（生产源码直编 + 最小 mock）：`bash tests/host/run.sh`
  —— plain 构建全过后，再以 `-fsanitize=address,undefined
  -fno-sanitize-recover=all` 全部重跑。套件：`test_parser`(20)、
  `test_rx_path`(8)、`test_rx_hostile`(2，独立二进制隔离崩溃)、
  `test_obs_cache`(6)、`test_hopper`(4)。
- 红/绿证据：commit `c307fbe`（重构+测试，缺陷未修）→ CI run
  **35904015317** host 套件在预期用例上失败（slot 泄漏/MISC 白名单/
  parse length/IE 三态/观察覆盖等），同 run 固件构建通过；修复序列
  `97f15b4..ae58b69`（含编译/测试修正 `e5dccbe`、`f4ebc73`）→ CI run
  **35907019585**（commit `f4ebc73`）全绿：host 40/40（plain 与
  ASan/UBSan 各 40）+ IDF v5.4/esp32c6 固件构建成功。
- 固件构建：GitHub Actions `ESP-IDF Build` job，IDF v5.4 / esp32c6，
  每次推送都验证；修复后构建通过。
- 现有推送授权范围内仅推送 `phase1.5-bugfix` 分支与 main 快进（与既有
  直接提交 main 的历史一致）；未做发布。

## 8. 内存影响

- 无任何新增动态分配；RX 路径仍是固定 24-slot pool
  （24×(512+12)B ≈ 12.4 KB 静态，不变）。
- `radio_stats_t`：删除 `ap_unique` 等单个 u32，加入 rx 嵌入结构（原
  字段平移）与 5 个 cache 计数 + occupied/u8，净增 ~20 B 静态。
- hopper 每信道健康状态 `s_health[14]`（每项 8 B，静态 ~112 B）。
- `obs_ap_result_t` 按值返回（16 B 栈），无堆。
- 栈：RX/解析任务栈尺寸不变（2048/3072）；hopper 2048 不变。

## 9. 已知限制与 Phase 2 交接

- coarse security 仍是 presence 级（RSN/WPA/PRIVACY/OPEN），无 suite
  解析；negative evidence 仅在 complete 观察成立。
- AP cache 仍是固定 32 槽 round-robin 去重缓存，无 TTL/老化/last_seen；
  "当前在线 AP 数"需要 Phase 2 的 World Model（AP DB + TTL）。
- MGMT `order` 位（HT 变长头）与分片 body 保守拒绝深解析——这些帧计数
  正常，但不产出观察；如需覆盖，Phase 2 需要先支持变长头。
- hopper 的瞬时错误"本轮跳过"依赖 pass 循环；若全部信道确定性退役，
  hopper 停止且 enabled=false，`current_channel` 保留最后已知值
  （0=unknown）。恢复需要重启或后续阶段的健康检查。
- `esp_wifi_get_country()` 返回值依赖驱动/PHY 初始化时序；查询失败路径
  已回退 1..11，但实际返回值（尤其 `01` 是否报告 nchan=11）需要实机确认
  （见 §10）。
- DEVELOPMENT.md 第 8 节的"Phase 1/2/3"是**跳频策略内部阶段**（现已改名
  HS-1/2/3），与项目阶段编号无关；下一**项目**阶段仍是 Phase 2
  （World Model）。

## 10. 实机回归（已完成，2026-09-24）

硬件 Waveshare ESP32-C6-Touch-LCD-1.9，COM3，烧录 CI 产物
`firmware-3e20b4736e157d268c48cdc6e5ba3b54a59f9366.zip`（GitHub Actions
run 35907863519，esptool v5.4.0 `write-flash` 校验通过）。
**固件 commit = 3e20b47 = 本文档所在提交，固件与日志一一对应。**

原始日志（未加工，本仓库内）：

- `docs/logs/phase15_boot_3e20b47.log` —— RTS 复位后从头采集的完整
  boot + 215 s 运行窗口。
- `docs/logs/phase15_stability_run1_3e20b47.log` —— 首次烧录后 200 s
  运行窗口（开表晚于 boot，boot 段以上一文件为准）。

Boot 段判据（全部满足）：

```text
I (434) phase1: esp32c6-Pwnagotchi Phase 1.5 bugfix baseline
I (439) phase1: firmware git commit: 3e20b4736e157d268c48cdc6e5ba3b54a59f9366 (3e20b47)
I (889) board_sd: SD mount: OK at /sd_card, size 0.95 GB
I (924/927) board_sd: SD write/read/verify: OK
I (1200) RADIO: promiscuous RX started on channel 6
I (1204) HOP: country 01 channels 1..11 (11 entries)   <- 缺陷 3 修复的实机确认
I (1209) HOP: hopping 11 channels, dwell=300 ms
I (1217) phase1: Phase 1 ready: LCD=OK I2C=OK Touch=OK SD=OK WiFi=SNIFFING HOP=ON
```

运行窗口判据（t=4 s .. 214.5 s，215 s 单次上电，无重启）：

```text
rx:            44 -> 4284（持续增长）
queued==processed: 4284 == 4284（队列零积压，q 峰值 2）
drop=0  st_err=0  misc=0          （计数恒等式成立）
trunc=68                          （>512 帧按边界截断并计数）
hops=710 (~10.1/s), errors=0      （实测信道集合恰为 1..11，无 12/13）
heap=199068 -> 199064, min_heap=194116（平坦，无持续下降）
APCACHE occ=26/32 ins=26 evict=0 skip=68
ie_err=0  ie_inc=66               （截断尾部计 incomplete，不再计 malformed）
berr=0  beacon=2972  preq=387  presp=124
crash/panic/watchdog/reboot 标记: 0
```

多信道发现（OBS 行节选，含 hidden 与非打印 SSID 清洗显示）：

```text
AP bssid=E2:C3:13:2F:E3:53 ssid="HUAWEI-CR16D8" rssi=-79 rx_ch=1 adv_ch=1 sec=RSN
AP bssid=78:11:DC:1E:89:80 ssid=".................." rssi=-85 rx_ch=2 adv_ch=2 sec=RSN
AP bssid=C2:7C:A6:79:B6:44 ssid=<hidden> rssi=-43 rx_ch=9 adv_ch=9 sec=RSN
AP bssid=DA:33:2A:21:60:00 ssid="@DLMU" rssi=-88 rx_ch=11 adv_ch=11 sec=OPEN
```

`skip=68 / ie_inc=66` 直接演示缺陷 5 的新语义：截断/不完整观察被计数并
跳过，不污染 cache；`ie_err=0` 而非历史上的 5 个 malformed，与
`ie_inc` 的分离使截断与坏帧不再混计。

保留说明：屏幕触摸交互仍为 init OK、实际触屏事件待维护者确认（与
Phase 1 相同，非本阶段回归项）。错误帧、无 payload MISC 与边界长度由
host 注入覆盖，未要求无线发射制造异常。

## 11. 提交清单

- `c307fbe` phase1.5: extract host-testable radio cores + regression tests (RED)
- `97f15b4` phase1.5 fix 1+2: slot ownership + payload type whitelist (rx_path)
- `2d51f7f` phase1.5 fix 3: country-table channel list + bounded hopper failure policy
- `6575f8e` phase1.5 fix 4: FCS/captured-length/IE boundary semantics in the parser
- `7604a61` phase1.5 fix 5: incomplete observations never degrade cached knowledge
- `ae58b69` phase1.5 fix 6: AP cache statistics semantics (UI + serial)
- `3e20b47` docs: Phase 1.5 bugfix acceptance record（本文档）
- 实机日志：`docs/logs/phase15_boot_3e20b47.log`、`docs/logs/phase15_stability_run1_3e20b47.log`

## Phase 1.5 验收状态

- 代码 + 自动回归（host 40/40，plain + ASan/UBSan）：**PASS**
- ESP-IDF v5.4 / esp32c6 固件构建：**PASS**（run 35907019585 / 35907863519）
- 实机回归（boot + 215 s 稳定窗口，§10 全部判据）：**PASS**
  （固件 3e20b47，日志 docs/logs/phase15_*.log）

**PHASE 1.5: PASS**

下一阶段为 Phase 2（World Model），未提前开工。
