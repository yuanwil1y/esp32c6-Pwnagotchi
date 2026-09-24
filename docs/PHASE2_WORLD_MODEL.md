# Phase 2 — World Model：实现与验收

基线：`9738af2`（Phase 1.5 实机验收 PASS，固件 3e20b47）。本阶段实现
AP DB、STA DB、保守的 AP↔STA 观察关系、TTL 老化、RSN/WPA security
parser 与最小 UI/统计接入。全程保持被动监听：callback 仍无分配/日志/
阻塞/复杂解析，vendor 只读，不主动扫描或发包。EAPOL、PCAP、SD logger、
Epoch、Personality、完整 UI 与自适应跳频仍属后续阶段。

## 0. 结果概览与验收状态

| 项 | 状态 | 证据 |
|---|------|------|
| 2A AP DB（host 测试 + IDF 构建） | PASS | CI run 35953748323（commit 40dd701） |
| 2B STA DB + 关系（host 测试 + IDF 构建） | PASS | CI run 35954791715（commit e883eb7） |
| 2C security parser（host 测试 + IDF 构建） | PASS | run 35955317691（6e9d9a4） |
| 2D 接入/文档（host 测试 + IDF 构建） | PASS | run 35955699646（c2e7ee4） |
| Phase 1.5 回归保留 | PASS | 同上（callback/IE 套件原样运行） |
| 实机验收（≥1 min 稳定 + 受控 AP 对照） | **PENDING** | 见 §8 待执行清单 |

分支 `phase2-world-model`（未合并 main；固件 commit SHA 见 §8）。
host 套件 9 个二进制共 95 用例，plain 与 ASan/UBSan 各跑一遍，全部
编译生产源码（`ieee80211_parser.c` / `rx_path.c` / `obs_cache.c` /
`hopper_policy.c` / `world.c`），无一测试重实现生产逻辑。

## 1. 架构与数据流

```text
promiscuous callback (driver task, 不变)
  └─ rx_path core: 类型白名单 → rx_state 门禁 → 24-slot pool 有界复制
       └─ FreeRTOS queue
            └─ radio_rx_task（唯一 world 写者）
                 ├─ ieee80211_parse（FC 分类）
                 ├─ beacon/probe resp → parse_beacon_or_probe_resp → world_on_ap_observation
                 ├─ probe req        → parse_probe_request          → world_on_probe_request
                 ├─ auth/assoc/reassoc req                          → world_on_sta_mgmt_tx
                 ├─ data（含 Null/QoS/受保护）→ parse_data_addresses → world_on_data_frame
                 └─ 每 ≤500 ms 或队列 100 ms 超时 → world_maintenance（TTL/淘汰）
radio_stats_task / phase1_ui_task（只读者）
  └─ wifi_sniffer_get_stats：task-level mutex 下复制 ~88 B 快照，
     从不在关中断临界区复制数据库，持锁期间不做 LVGL/日志/SD 操作
```

- world 是纯 C 值域代码：无 FreeRTOS/LVGL/驱动/堆依赖，时间一律为
  调用方传入的 uint64 毫秒（host 测试用虚拟时钟驱动全部时间行为）。
- world 初始化先于 RX 任务创建与 `esp_wifi_start()`（wifi_sniffer_init
  内顺序保证）。
- 观察是值类型：解析产物以值传递/复制进 DB，不长期持有 packet pool
  指针。
- 事件口径：本阶段不建通用事件总线；快照（`world_snapshot`）始终
  提供真实当前状态，发现日志沿用 Phase 1.5 的限流去重缓存。

## 2. 数据结构与内存预算

容量与 TTL 均为具名常量（`world.h`），是起始值而非已验证硬件结论；
实机 heap 趋势确认后可再调（Phase 1.5 实测 min_heap≈194 KB，本阶段
静态占用对 heap 无压力）：

```c
#define WORLD_AP_MAX      64      /* AP 记录容量        */
#define WORLD_STA_MAX     128     /* STA 记录容量       */
#define WORLD_AP_TTL_MS   120000  /* AP 观察过期        */
#define WORLD_STA_TTL_MS  120000  /* STA 观察过期       */
#define WORLD_REL_TTL_MS  60000   /* 关系证据过期       */
```

ILP32（esp32c6）下按结构体布局规则计算（boot 日志
`world: sizeof(world_t)=...` 会在实机再确认一次）：

| 类型 | sizeof | 数量 | 小计 |
|---|---|---|---|
| `world_ap_t` | 104 B | 64 | 6656 B |
| `world_sta_t` | 64 B | 128 | 8192 B |
| `world_stats_t` + 计数字段 | 86 B | 1 | 86 B |
| **world_t 合计（静态 BSS）** | | | **≈14.6 KB** |
| `world_snapshot_t`（栈上复制） | 88 B | — | 每读者一次 |
| `radio_stats_t` 增量 | ≈86 B | 1 | 静态 |

- 无任何新增动态分配；无新任务（world 运行在 radio_rx_task 内）。
- 队列/快照/锁开销：1 个 FreeRTOS mutex；每条 world 输入为短临界区
  （O(64) 或 O(128) 的线性查表 + 常数合并），无整库复制路径。
- 栈：radio_rx 2048 B / radio_stat 3072 B 不变；实机用新增的
  `stk_rx`/`stk_stat`（uxTaskGetStackHighWaterMark）确认余量（§8）。

**AP 记录**（BSSID 唯一键）：raw SSID bytes + len + known、
first/last_seen、接收信道（last_rx_channel）与宣告信道（DS IE）、
security 描述 + 状态、AP 自发帧 RSSI、beacon/probe_resp/data 上下行
饱和计数、station_count、provisional 标志。SSID 仅在输出边界 sanitize。

**STA 记录**（MAC 唯一键，语义是"观察到的地址"而非物理设备）：
first_seen、last_tx_seen（自发帧）与 last_observed（含下行目的）分离、
自发帧 RSSI、probe/tx/dl 计数、locally_administered 标志（随机化 MAC
各占一条记录，只标记不合并）、当前 observed AP（rel_ap/rel_evidence/
rel_last_evidence）。

## 3. 关键语义决策

### 3.1 AP 合并策略（world_on_ap_observation）

- 活动（last_seen/信道/RSSI/beacon 计数）对每个到达解析器的观察刷新，
  无论 complete 与否（帧已收到、头部已过边界检查）。
- SSID：仅 COMPLETE 且非 hidden 的观察可设置/替换名称；hidden（全零
  或零长）与缺失永不清除已学名称。完整合法的新名称可更新（重命名）。
- 重复关键 IE（SSID/DS）：parser 首个生效 + `dup_critical_ie`（Phase
  1.5 语义不变），导致 incomplete → 不做字段合并。
- 宣告信道：DS IE 为原子 3 字节，凡完整解析且值合法（1..14）即采用
  （截断捕获中亦然）；缺失从不清零。
- 仅接纳有效单播非零 BSSID；Probe Request 永不创建 AP。
- data 推断出的 AP 为 PROVISIONAL（不伪造 SSID/security），收到该
  BSSID 的 beacon/probe response 后转正；uplink data 的 RSSI 属于
  STA，绝不写入 AP.rssi。

### 3.2 容量与确定性淘汰

- 空位优先取最低槽位；满表先做过期清扫，仍满时：
  - 强创建者（beacon/probe resp 之于 AP；任何 STA 自发帧之于 STA）
    可淘汰 last_seen/last_observed 最旧者，平局取最低槽位（可测试）；
  - 弱创建者（data 推断 AP、纯下行目的 STA）永不淘汰，拒绝并计数
    （ap_rejected / sta_rejected）。
- expired / evicted / rejected 全部计数并每 3 s 汇出。

### 3.3 数据帧地址映射（world_on_data_frame）

`ieee80211_parse_data_addresses` 按 FC 计算最小头长（24 + 四地址 6 +
QoS 2 + HT Control 4），逐字节、全边界检查地提取 addr1..4；受保护帧
的明文 MAC 头照常可用，加密 body 永不解析。四象限处理：

| ToDS | FromDS | 处理 |
|---|---|---|
| 1 | 0 | BSSID=addr1，STA=addr2（发送方，RSSI 归 STA）；addr3 为 DS 侧目的，**不**计为无线 STA |
| 0 | 1 | BSSID/TA=addr2（RSSI 归 AP）；单播 addr1 为 STA 候选（下行证据）；addr3 为 DS 侧源，**不**计为无线 STA |
| 0 | 0 | 跳过基础设施推断，计 data_ambiguous（IBSS/直连混淆） |
| 1 | 1 | WDS/四地址：边界验证后跳过普通推断，计 data_wds |

- 广播/组播/全零地址与 AP 自身地址永不成为 STA；STA==BSSID 的
  uplink 拒绝（obs_invalid）。
- Probe Request 只发现源 STA（wildcard 与定向 SSID 均不建立关系）；
  同一 MAC 重复 Probe 仍是一条记录。auth/(re)assoc **请求**只刷新
  STA tx 证据（SA 可能是 AP 的 deauth/disassoc/action 不喂）。
- `last_tx_seen` 与 `last_observed` 严格分离：AP 向离线目的的重传
  不构成"该 STA 仍在线"的证据（下行不刷新 last_tx、不写 STA RSSI）。

### 3.4 关系模型（每 STA 一个当前 observed AP）

- 证据强度：UPLINK(2) > DOWNLINK(1)；同强度比新鲜度（新者胜）。
  切换条件：`新证据 > 旧证据` 或 `相等且更新`；弱于现绑定的证据只
  计冲突（rel_conflicts）不切换，绝不丢更强/更新证据。
- 关系含义是 observed/inferred，不宣称关联成功；本阶段不实现关联
  状态机，也不以单个 deauth/disassoc 断言掉线。
- TTL：关系证据 60 s 过期 → 解绑（STA 记录留存至自身 120 s TTL）。
  **TTL 表示观察过期，不显示为"已断开"**。
- AP 过期/淘汰先解绑其全部关系（槽复用不可能让旧关系指向新 AP）；
  STA 过期/淘汰先解绑再释放。
- 不变量 `AP.station_count == 当前绑定到该 AP 的 STA 数`在每次
  bind/unbind/移除时维护，并由 `world_check_invariants` 在测试中
  每步校验；重复帧不累加，切换/TTL/淘汰不下溢。

### 3.5 Security（Phase 2C）

parser 对 RSN IE（48）与 WPA vendor IE（221, 00:50:F2:01）做严格解码：
version（必须为 1）、group cipher、pairwise cipher 集合、AKM 集合、
可选 RSN capabilities（MFPC=bit7 / MFPR=bit6）。suite count 一律用
`count > remaining/4` 的除法校验（绝不做乘法）；IE 声明体必须完整落在
捕获内才解码（截断在 IE 内部时 walk 报 incomplete，绝不产出半个
suite）。缺 AKM 列表/缺 caps 合法；caps 声明存在但被捕获截断 →
incomplete（与"缺失"区分）。上下文 OUI 错配（RSN 用 00:50:F2 或
WPA 用 00:0F:AC 的 suite）解码为 UNKNOWN；未知 AKM 绝不标成 PSK。

world 合并：

- 任一观察（含截断捕获）中**完整合法解析**的 RSN/WPA IE 是正向
  证据：套用其 suites，状态 KNOWN（"尚未捕获到"≠"不存在"）；
- 仅 COMPLETE 且无 RSN/WPA 的观察才可下结论：privacy=0 → OPEN，
  privacy=1 → LEGACY_PRIVACY（**绝不断言 WEP**）；
- COMPLETE 但 security IE 畸形：不覆盖已知有效结果（仅刷新头部
  privacy 位）；畸形 security IE 使 walk 停止、观察 incomplete。
- 同一 AP 完整/截断 beacon 交替不产生安全标记抖动（fixture 覆盖）。

显示命名 `world_security_name` 仅基于已验证字段组合：WPA2-PSK /
WPA2-1X / WPA3-SAE / WPA3-OWE / WPA2/WPA3（PSK+SAE transition）/
WPA/WPA2（双 IE）/ WPA-PSK / WPA-1X / PRIVACY / OPEN / UNKNOWN，
无法识别的集合带 `-?`，PMF 记为 `-PMF` / `-PMF(req)`。RSN 存在
本身绝不等于 WPA2-PSK。

## 4. 可观测性

- UI 状态页（2 Hz）：`CH / AP / STA(obs) / REL / RX / DROP` ——
  AP 为 DB 当前有效记录数（替代 Phase 1.5 的日志缓存占用）；
  `STA(obs)` 表达"观察到的 STA 地址"，对随机化 MAC 不作物理设备
  承诺。
- 串口每 3 s：
  - `RADIO ... heap= min_heap= stk_rx= stk_stat=`（新增任务栈余量，
    uxTaskGetStackHighWaterMark）；
  - `WORLD ap= sta= rel= A:cre/exp/ev/rej S:cre/exp/ev/rej R:new/exp/
    sw/cfl amb= wds= short= stale= invalid=`（created/expired/evicted/
    rejected、关系冲突、ambiguous/WDS/短头计数）；
  - 原有 CH/RX/DROP、80211 分类、APCACHE、HOP 行保留（APCACHE 行
    语义仍是日志缓存，见 Phase 1.5）。
- OBS 行的 `sec=` 输出改为 world 合并态的命名 security（对齐
  `world_security_name`），每次输出前在锁内做一次 ≤64 槽的页扫描
  （仅限流日志路径）。

## 5. 与 Phase 1.5 契约的关系

- 解析状态与字段有效性契约沿用：malformed_ie / ie_walk_incomplete /
  dup_critical_ie / complete 语义不变；capture 截断与 malformed 不
  混计。2C 只是在 RSN/WPA IE 内部增加了结构校验（畸形结构计入
  malformed_ie，Phase 1.5 的 `beacon_typical_fields` fixture 原本
  编码了一个 AKM count 无 suite 字节的非法 RSN，已更正为合法 RSN，
  断言不变）。
- callback/IE 回归（slot 守恒、MISC 零 payload、队列满恢复、错误帧
  超容量、FCS/IE 边界三态、SSID 0/32/33/全零/重复、已知名后 hidden
  等）全部保留并每条 CI 运行。
- obs_cache（32 槽日志去重）保留原语义，仅用于日志节流；不再是
  UI 的 AP 指标来源。

## 6. 测试与 CI 证据

host 套件（`bash tests/host/run.sh`，plain 后 ASan+UBSan
`-fno-sanitize-recover=all` 重跑）：

| 套件 | 用例 | 覆盖 |
|---|---|---|
| test_parser（Phase 1.5） | 20 | FC/IE 边界三态、SSID/DS/重复/FCS（原样保留） |
| test_rx_path / test_rx_hostile（Phase 1.5） | 8+2 | slot 守恒、错误帧>24、MISC 零 payload、队列满恢复、敌意输入 |
| test_obs_cache / test_hopper（Phase 1.5） | 6+4 | 观察合并护栏、信道表/hopper 策略 |
| test_world（2A） | 16 | 创建/合并、hidden 不清名、截断部分更新、DS 正向证据、complete 权威、无效 BSSID、stale、TTL 边界、无包 maintenance、容量淘汰+平局、满表先清过期、churn 有界、页导出、parser→world e2e |
| test_data_addrs（2B） | 6 | 四象限 DS、头长算术（QoS/四地址/HTC）、短头、协议版本、受保护帧、广播/组播 |
| test_world_sta（2B） | 20 | RSSI 归属、DS 侧地址不污染、上下行同一 STA、provisional 转正、广播/自地址排除、probe 只发现 STA、证据强度/切换/冲突、关系 60 s vs STA 120 s、AP 过期解绑、stale、槽复用不悬挂、弱创建者不淘汰、ambiguous/WDS、churn 不变量 |
| test_security（2C） | 13 | RSN PSK/1X/SAE/OWE/transition/GCMP、WPA vendor、OUI 区分、未知 suite、count 越界、version/短体、可选尾（缺 caps 合法 / 截断区分）、长 beacon 截断在 RSN 前/内/后、valid→malformed 不降级、截断正向证据升级、命名 |

CI（GitHub Actions `ESP-IDF Build`）：host-tests job（plain+ASan/UBSan）
与 ESP-IDF v5.4/esp32c6 固件构建并行，每次 push 验证。

- 2A 全绿：run **35953748323**（40dd701；此前 2A 首推 e9f2432 有一个
  const 限定错误与一个测试 BSSID 组播位笔误，分别由 6775fbf、40dd701
  修复）。
- 2B 全绿：run **35954791715**（e883eb7；f3794eb 首推暴露
  `ap_remove` 未清 station_count 的真缺陷 + 两个测试时间线错误，由
  91e10be/e883eb7 修复，见提交说明）。
- 2C 全绿：run **35955317691**（6e9d9a4；b862765 首推暴露 Phase 1.5
  fixture 非法 RSN 与一处测试指针笔误，6e9d9a4 修复）。
- 2D 全绿：run **35955699646**（c2e7ee4）＝本分支最新代码提交；该
  run 的 `firmware-c2e7ee4…zip` 即实机验收烧录产物（§8）。后续的
  docs-only 提交不改代码路径。

## 7. 已知限制与 Phase 3 交接

- 关系为观察级：无关联状态机、无 auth/assoc status 解码、无
  deauth/disassoc 语义；一次 deauth 不代表掉线。
- MGMT order 位（HT 变长头）与分片 body 仍保守拒绝深解析（Phase 1.5
  限制不变）；data 路径已按 FC 计算 HT Control 头长。
- 随机化 MAC 无法等同物理设备；UI/计数语义为"观察到的地址"。
- 淘汰平局与槽位策略为确定但朴素（最低槽位）；如需保热点 AP 可在
  实机数据后引入活跃度权重。
- sta/rel 满表拒绝仅计数；容量是否需要调优以实机 heap/HWM 为准。
- 8h/24h soak、EAPOL/PCAP、自适应 dwell 均属后续阶段。

## 8. 实机验收（PENDING —— 待执行清单）

> 硬件 Waveshare ESP32-C6-Touch-LCD-1.9。维护者执行前不改代码；
> 结果回填本节并把状态改为 PASS/FAIL（不可用编译通过冒充实机 PASS）。

烧录：CI run 35955699646 产物 `firmware-c2e7ee4736….zip`（固件
commit SHA = c2e7ee4 = 最新代码提交；esptool v5.4 write-flash 自带
校验）。精确步骤（维护者实机执行，COM 口按 Phase 1.5 为 COM3）：

```bash
unzip firmware-<SHA>.zip -d fw2d
esptool.py --chip esp32c6 --port COM3 --baud 460800     --before default-reset --after hard-reset write-flash     @flash_args
# 或按 flasher_args.json 分区地址逐 bin 烧写；RTS 复位后重新开表
```

记录固件 commit SHA：**c2e7ee4**（boot 段
`firmware git commit:` 行与之一一对应）。

稳定运行 ≥1 分钟判据（对照 Phase 1.5 §10 风格）：

```text
I (...) phase1: esp32c6-Pwnagotchi Phase 2 World Model baseline
I (...) RADIO: world: sizeof(world_t)=... (AP 104B x64, STA 64B x128, static)
SD mount/self-test OK，promiscuous RX started，HOP country 01 channels 1..11
WORLD 行 ap/sta/rel 与环境一致且稳定（无持续下跌/爆炸）
drop=0（或可解释）、queue peak 有界、heap/min_heap 平坦
stk_rx/stk_stat 无趋零；无 reboot/panic/watchdog
```

受控 AP+客户端对照项：

1. 同 SSID 两个 BSSID → AP=2 独立计数（同 SSID 不合并）；
2. 一台客户端上下行 → STA=1（不重复）、REL=1；
3. 客户端仅发 Probe → STA+1、AP/REL 不变；
4. 停止客户端流量 >60 s → rel 过期（REL--），>120 s → STA/AP 记录
   过期（计数回退，不显示"已断开"）；
5. 客户端在 AP1/AP2 间切换 → rel_switched+1、station_count 迁移；
6. 已知 open/WPA2/WPA3 AP 的 OBS `sec=` 与真值对照（OPEN/WPA2-PSK/
   WPA3-SAE 等）；
7. LCD 状态页 CH/AP/STA(obs)/REL/RX/DROP 正常刷新，触摸 init OK，
   SD 自检 OK，跳频固定 300 ms，无主动扫描/发包。

判据数据回填：流量强度（rx/s）、queue peak/drop、heap 起止与
min_heap、stk_rx/stk_stat 最小值、世界计数终值、崩溃标记 0。

## 9. 提交清单（phase2-world-model 分支）

- `e9f2432` phase2a: world component - AP database with TTL and deterministic eviction
- `6775fbf` phase2a fix: drop const qualifier in eviction victim scan
- `40dd701` phase2a test fix: e2e beacon BSSID must be unicast
- `f3794eb` phase2b: STA database and conservative AP<->STA observation relations
- `91e10be` phase2b fix: remove unused sta_index helper
- `e883eb7` phase2b fix: ap_remove resets station_count; correct test timelines
- `b862765` phase2c: strict RSN/WPA suite parser and world security merge
- `6e9d9a4` phase2c fix: legal RSN fixture in Phase 1.5 regression; pointer misuse
- `c2e7ee4` phase2d: UI/observability integration + docs

## Phase 2 验收状态

- 代码 + 自动回归（host，plain + ASan/UBSan）：**PASS**（§6）
- ESP-IDF v5.4 / esp32c6 固件构建：**PASS**（§6 最终 run）
- 实机回归：**PENDING**（§8）
