# esp32c6-Pwnagotchi

面向 **Waveshare ESP32-C6-Touch-LCD-1.9** 的 Pwnagotchi-like 固件项目。

本项目参考 Pwnagotchi 的交互体验、Epoch / Personality / Agent 思路，但运行平台改为 ESP32-C6 + ESP-IDF。首阶段采用**被动监听路线**：不依赖 Linux、不依赖 Bettercap，不把 deauth、主动 association/PMKID 或任意 802.11 帧注入作为 V1 目标。

## 当前状态

**Phase 2 - World Model 已完成并通过实机验收（固件 369729c：180 s 稳定运行 drop=0、heap 平坦、TTL 实测执行、WPA3 transition/多 BSSID 现网对照一致；受控漫游切换项留待维护者随客户端执行）。** 新增 `components/world`（纯 C、host 可测）：AP DB（BSSID 键、TTL 120 s、确定性淘汰）、STA DB（"观察到的地址"语义，随机化 MAC 单独记录）、保守 AP↔STA 观察关系（数据帧证据：uplink 强于 downlink、60 s 证据 TTL、station_count 不变量）、严格 RSN/WPA suite 解析（除法校验 count、MFPC/MFPR、未知 suite 不猜 PSK、PRIVACY 不断言 WEP）与基于已验证字段组合的显示命名。radio_rx_task 单写 world（有界队列等待 + 定时 maintenance，零流量/持续流量下 TTL 均执行）；状态页与 3 s 串口输出 AP/STA(obs)/REL 当前数、created/expired/evicted/rejected、关系冲突与任务栈余量。Phase 2.5 review 修复摘要、CI 固件与 1 分钟实机 smoke test 清单见 [docs/PHASE2_WORLD_MODEL.md](docs/PHASE2_WORLD_MODEL.md#10-phase-25-review-修复与交接)。

**Phase 1.5 - 缺陷修复与回归验收已完成（PASS）。** Phase 1 review 发现的六组缺陷已修复：RX slot 所有权泄漏（错误帧不再耗尽 24-slot pool）、MISC 零 payload 白名单（不再按 sig_len 读 payload）、信道表改为驱动 country 表（`01`/world-safe → 1..11）+ hopper 失败有界重试策略、FCS/IE 边界三态语义（截断不再当坏帧）、不完整观察不再覆盖已知 SSID/security/信道、AP 统计改为 `AP cache`（0..32 去重槽占用，非 total unique AP）。新增 host 生产代码回归测试（plain + ASan/UBSan）接入 CI。实机验收已通过（固件 3e20b47：`country 01 → 1..11`、10.1 hops/s errors=0、215 s 零 drop heap 平坦、无重启），日志见 [docs/logs/phase15_boot_3e20b47.log](docs/logs/phase15_boot_3e20b47.log)，完整验收记录见 [docs/PHASE1_5_BUGFIX.md](docs/PHASE1_5_BUGFIX.md)。

**Phase 1 — Passive Wi-Fi Sniffer 已全部完成并通过实机总验收（Phase 1A/1B/1C/1D）。** 当前系统：promiscuous RX → 轻量 callback → 固定容量队列 → 解析任务 → 802.11 分类 → Beacon/Probe IE 解析（SSID/BSSID/RSSI/信道/安全基础分类）→ 独立 Channel Hopper Task 以 300ms dwell 在合法信道循环；LCD/LVGL/Touch/SD 正常共存。总验收记录见 [docs/PHASE1_FINAL.md](docs/PHASE1_FINAL.md)。

**Phase 1D - Channel Hopper 已实现并通过实机验收。** `components/radio/channel_hopper`：独立 FreeRTOS task，合法信道表自 `esp_wifi_get_country()` 的 schan/nchan 生成（驱动默认 country `01` 为 world-safe 1..11；表缺失/非法时回退 1..11；如 CN 表为 1..13），固定 300ms dwell 顺序循环；确定性无效信道运行时退役，瞬时错误有界重试后本轮跳过（不退役），绝不 abort。验收记录同上；Phase 1.5 语义修正见 [docs/PHASE1_5_BUGFIX.md](docs/PHASE1_5_BUGFIX.md)。

**Phase 1B - 802.11 Frame Classification 已实现并通过实机验收。** `components/radio` 新增 `ieee80211_parser`：消费任务中对原始 Frame Control 做小端字节组装 + mask/shift 解码（无结构体覆盖、无位域映射），分类 Management / Control / Data 及各 subtype（beacon / probe / auth / RTS / ACK / QoS Data 等），并与 ESP-IDF 驱动分类交叉核对；串口每 3 秒输出分类统计。验收记录见 [docs/PHASE1B_80211_CLASSIFICATION.md](docs/PHASE1B_80211_CLASSIFICATION.md)。

**Phase 1A - Wi-Fi Promiscuous RX 已实现并通过实机验收。** `components/radio` 提供 promiscuous RX：极轻量 callback → 固定容量 packet pool + 队列 → 消费任务计数，3 秒周期串口统计输出，LVGL 状态页 2 Hz 刷新，本阶段无协议解析。验收记录见 [docs/PHASE1A_WIFI_PROMISCUOUS_RX.md](docs/PHASE1A_WIFI_PROMISCUOUS_RX.md)。

**Phase 0 - Board Bring-up 已实现。** 当前工程已经从 Waveshare FactoryProgram 中抽出最小 board 层，包含 LCD/LVGL、Touch、SD、I2C 和背光；LVGL 运行在独立 FreeRTOS Task 中。

硬件实机验收重点见 [docs/PHASE0_BOARD_BRINGUP.md](docs/PHASE0_BOARD_BRINGUP.md)。

## 硬件基线

官方 Waveshare 工程以 Git submodule 引入到：

`vendor/waveshare`

当前硬件参考工程：

`vendor/waveshare/02_Example/ESP-IDF/08_FactoryProgram`

该官方工程覆盖 LCD、触摸、SD、Wi-Fi、ADC、IMU、LVGL 等板级能力，可作为本项目的 bring-up / 引脚 / 驱动参考。`vendor/waveshare` 保持只读，本项目代码位于自己的 `main/` 和 `components/` 中。

克隆仓库时请带上 submodule：

```bash
git clone --recursive https://github.com/yuanwil1y/esp32c6-Pwnagotchi.git
```

已有仓库补拉：

```bash
git submodule update --init --recursive
```

## Phase 0 构建

建议使用 ESP-IDF 5.4.x，与 Waveshare FactoryProgram 的开发环境保持一致：

```bash
idf.py set-target esp32c6
idf.py build
idf.py -p <PORT> flash monitor
```

首次构建会通过 IDF Component Manager 获取 `espressif/esp_lcd_sh8601` 和 LVGL 8.3.11。

## 项目方向

V1 计划实现：

- ESP32-C6 Promiscuous Wi-Fi RX
- 自动信道轮询
- 802.11 Beacon / Probe / Data / EAPOL 被动解析
- AP / Station 数据模型与 AP ↔ STA 关系维护
- 被动握手/EAPOL 事件检测与 SD 卡记录
- PCAP/PCAPNG 记录
- Pwnagotchi 风格 Epoch / Personality / 表情状态
- LVGL UI 与触摸菜单
- 运行统计、配置持久化与长期稳定性优化

详细设计、边界和开发路线见 [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)。

## 参考

- Pwnagotchi: https://github.com/jayofelony/pwnagotchi
- Waveshare ESP32-C6-LCD-1.9: https://github.com/waveshareteam/ESP32-C6-LCD-1.9
- ESP-IDF: https://github.com/espressif/esp-idf

> 主动无线交互能力不属于 V1 范围。
