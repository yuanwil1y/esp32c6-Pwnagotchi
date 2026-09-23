# esp32c6-Pwnagotchi 开发文档

## 1. 项目目标

本项目面向 **Waveshare ESP32-C6-Touch-LCD-1.9**，目标是在 ESP32-C6 上实现一个具有 Pwnagotchi 核心交互体验的独立固件。

参考项目：

- Pwnagotchi: https://github.com/jayofelony/pwnagotchi
- Waveshare ESP32-C6-LCD-1.9: https://github.com/waveshareteam/ESP32-C6-LCD-1.9
- ESP-IDF: https://github.com/espressif/esp-idf

本项目**不尝试直接运行原版 Pwnagotchi Python/Bettercap 软件栈**。我们参考其上层行为模型与用户体验，并在 ESP-IDF / FreeRTOS 上重新实现。

## 2. V1 范围

### 2.1 必须实现

1. 板级基础
   - LCD 初始化
   - 触摸输入
   - SD 卡
   - I2C
   - 电量/ADC
   - IMU（可选用于交互扩展）

2. Wi-Fi 被动监听
   - Promiscuous mode
   - Channel hopping
   - Management / Data / Control frame 接收
   - RSSI / channel 元数据采集

3. 802.11 解析
   - Beacon
   - Probe Request / Response
   - Authentication / Association 观察
   - Data frame 地址字段
   - EAPOL 检测
   - RSN / WPA/WPA2 安全能力解析

4. World Model
   - AP 数据库
   - STA 数据库
   - AP ↔ STA 关系
   - first_seen / last_seen / TTL
   - RSSI / channel / security / activity
   - 事件总线

5. Pwnagotchi-like Agent
   - Epoch
   - active_for / inactive_for
   - bored / sad / excited 等状态
   - Personality 参数
   - channel dwell 策略
   - AP/STA 活跃度驱动的状态变化

6. UI
   - Pwnagotchi 风格表情
   - 当前状态文字
   - Channel / AP / STA / RSSI / uptime
   - SD 状态
   - 触摸设置页

7. 存储
   - NVS 配置
   - SD 日志
   - PCAP/PCAPNG
   - 统计信息持久化

### 2.2 V1 明确不做

V1 不把以下能力作为目标：

- deauthentication
- 主动 association / PMKID 获取
- 任意 802.11 frame injection
- Bettercap 命令兼容层
- 原版 Python plugin ABI
- Linux/systemd/web stack 兼容

原因是 ESP32-C6 官方 Wi-Fi API 对 TX frame 类型和 MAC 层控制能力有限，而被动监听与上层行为逻辑并不存在同等级别的硬件阻碍。

## 3. 官方底座

Waveshare 官方仓库通过 submodule 引入：

`vendor/waveshare`

硬件基线：

`vendor/waveshare/02_Example/ESP-IDF/08_FactoryProgram`

该工程已经验证/覆盖：

- 170x320 LCD
- 触摸
- LVGL
- SD 卡
- I2C
- Wi-Fi
- ADC
- QMI8658
- 板载按键/背光/RGB 等

我们的原则：

- vendor 目录保持只读
- 不直接修改官方源码
- 从官方工程提取并封装 board 层
- 所有 Pwnagotchi 逻辑放在本仓库自己的组件中

## 4. 推荐架构

```text
app_main
  |
  +-- board/
  |    +-- display
  |    +-- touch
  |    +-- sd
  |    +-- power
  |    +-- imu
  |
  +-- radio/
  |    +-- wifi_sniffer
  |    +-- channel_hopper
  |    +-- ieee80211_parser
  |
  +-- world/
  |    +-- ap_db
  |    +-- station_db
  |    +-- events
  |
  +-- agent/
  |    +-- epoch
  |    +-- personality
  |    +-- strategy
  |
  +-- storage/
  |    +-- config
  |    +-- pcap
  |    +-- stats
  |
  +-- ui/
       +-- face
       +-- status
       +-- menu
```

## 5. FreeRTOS 任务模型

Wi-Fi promiscuous callback 不做重活。

推荐数据流：

```text
ESP Wi-Fi driver
      |
      v
RX callback
  - 最小化复制
  - 写入 queue/ring buffer
      |
      v
Parser Task
  - 解析 802.11
  - 生成标准事件
      |
      v
World Model
  - AP DB
  - STA DB
  - activity
      |
      +------> Agent Task
      |          - Epoch
      |          - Personality
      |          - Strategy
      |
      +------> Logger Task
      |          - PCAP
      |          - stats
      |
      +------> UI Task
                 - LVGL
                 - touch
```

禁止：

- 在 promiscuous callback 内写 SD
- 在 promiscuous callback 内刷新 LVGL
- 在 promiscuous callback 内做复杂 frame parse
- 多个任务无锁修改同一个 AP/STA 容器

## 6. 核心数据模型

### AP

建议字段：

```c
typedef struct {
    uint8_t bssid[6];
    char ssid[33];

    int8_t rssi;
    uint8_t channel;

    uint32_t first_seen_ms;
    uint32_t last_seen_ms;

    uint16_t beacon_count;
    uint16_t data_count;
    uint16_t station_count;

    uint32_t security_flags;
} pwn_ap_t;
```

### Station

```c
typedef struct {
    uint8_t mac[6];
    uint8_t bssid[6];

    int8_t rssi;

    uint32_t first_seen_ms;
    uint32_t last_seen_ms;

    uint32_t frame_count;
} pwn_station_t;
```

## 7. Pwnagotchi 参考逻辑

我们参考 Pwnagotchi 的以下概念，不要求源码级兼容：

- Epoch
- Personality
- Agent
- active / inactive 计数
- bored / sad / excited 等情绪状态
- 根据无线环境变化调整行为
- 当前状态驱动 UI 表情和文本

建议 Epoch 状态：

```c
typedef struct {
    uint32_t number;

    uint16_t active_for;
    uint16_t inactive_for;
    uint16_t blind_for;

    uint16_t bored_for;
    uint16_t sad_for;

    uint16_t aps_seen;
    uint16_t stations_seen;
    uint16_t eapol_events;

    uint32_t duration_ms;
} pwn_epoch_t;
```

## 8. Channel Hopping 策略

第一版不要过度智能化。

注意：本节的 HS-1 / HS-2 / HS-3 是**跳频策略自身的阶段**（Hopping
Strategy stage），不是项目的开发阶段编号；项目阶段见第 11 节。两者曾经
都写作 "Phase 1/2/3"，容易混淆，现已区分命名。

HS-1（已实现，Phase 1D / Phase 1.5）：

- 固定信道表轮询（表来自 esp_wifi_get_country() 的 schan/nchan，缺失或
  非法时保守回退 1..11，见 docs/PHASE1_5_BUGFIX.md §4）
- 每信道固定 dwell time（300 ms）
- 记录 AP/STA 活跃度
- 确定性无效信道退役；瞬时错误有界重试/本轮跳过，不退役

HS-2（对应项目 Phase 2 之后的跳频增强）：

- 对活跃信道增加 dwell
- 对长时间空闲信道减少 dwell
- 对有 STA 的 AP 所在信道增加权重

HS-3（对应项目 Agent/UI 阶段）：

- Personality 参数参与跳频决策
- Epoch 活跃度影响 scan 策略

## 9. PCAP 设计

被动捕获直接写 PCAP/PCAPNG。

注意：

- RX callback 只入队
- Logger Task 批量写 SD
- 使用缓存减少 FAT 写放大
- 文件按大小/时间滚动
- 掉电前无法保证最后一个缓存块落盘，因此周期性 flush

第一阶段先保证：

- radiotap-like 元数据或自定义 metadata 能保留 channel/RSSI
- 原始 802.11 payload 不被破坏
- Wireshark 可打开

## 10. UI 路线

不要先复刻全部原版界面。

V0 UI：

```text
(•‿•)

CH 6
AP 12
STA 7
-47 dBm

scanning...
```

随后加入：

- AWAKE
- BORED
- SAD
- HAPPY
- EXCITED
- SLEEPING

触摸菜单：

- Wi-Fi stats
- Channel stats
- Storage
- Personality
- Brightness
- About

## 11. 开发阶段

### Phase 0 - Board Bring-up

目标：

- 官方工程能在目标板运行
- LCD
- Touch
- SD
- I2C
- 串口日志

完成标准：

- 屏幕显示项目名
- 触摸坐标正常
- SD 创建/读取测试文件

### Phase 1 - Wi-Fi Sniffer

目标：

- Promiscuous RX
- 1/6/11 或 1-13 channel hopping
- Beacon parser

完成标准：

串口稳定输出：

```text
CH=6 BSSID=AA:BB:CC:DD:EE:FF RSSI=-48 SSID=example
```

### Phase 1.5 - 缺陷修复与回归验收（当前阶段）

目标：

- 修复 Phase 1 review 发现的六组潜在缺陷（RX slot 泄漏、MISC 零
  payload、信道表/hopper 异常、FCS/IE 边界、不完整观察覆盖、AP 统计
  语义）
- host 可运行的生产代码回归测试接入 CI（plain + ASan/UBSan）
- 实机回归验收（硬件可用时）

完成标准：

- CI host 测试与固件构建全绿；实机项见 docs/PHASE1_5_BUGFIX.md §10

### Phase 2 - World Model（下一项目阶段）

目标：

- AP DB
- Station DB
- AP ↔ STA
- TTL
- security parser

完成标准：

- AP/STA 数量稳定
- 不发生明显内存泄漏
- 长时间运行不崩溃

### Phase 3 - EAPOL / PCAP

目标：

- EAPOL 检测
- PCAP 保存
- SD logger task

完成标准：

- Wireshark 可打开生成文件
- 能看到被动捕获的管理帧/数据帧

### Phase 4 - Agent

目标：

- Epoch
- Personality
- 状态变化
- channel dwell 策略

完成标准：

- 环境活跃度变化会驱动 Agent 状态变化

### Phase 5 - Pwnagotchi UI

目标：

- 表情
- 状态文字
- AP/STA/channel/statistics
- Touch menu

### Phase 6 - 稳定性

目标：

- 8h / 24h soak test
- heap 监控
- queue overflow 统计
- SD 故障恢复
- Wi-Fi 驱动异常恢复
- 看门狗策略

## 12. 目录规划

目标目录：

```text
.
├── CMakeLists.txt
├── sdkconfig.defaults
├── README.md
├── docs/
│   └── DEVELOPMENT.md
├── main/
│   ├── CMakeLists.txt
│   └── app_main.c
├── components/
│   ├── board/
│   ├── radio/
│   ├── world/
│   ├── agent/
│   ├── storage/
│   └── pwn_ui/
└── vendor/
    └── waveshare/   # git submodule
```

## 13. 设计原则

1. 官方 API 优先
2. 不依赖私有 Wi-Fi patch
3. radio 与 agent 解耦
4. callback 中只做最小工作
5. 数据结构固定上限或显式内存预算
6. 所有长期任务必须有 watchdog/health 指标
7. vendor 不直接修改
8. 上层逻辑不依赖具体屏幕/触摸实现

## 14. 第一批实际开发任务

按顺序：

1. 引入 Waveshare submodule
2. 建立最小 ESP-IDF 工程
3. 抽出 board display/touch/sd 初始化
4. 做项目启动页
5. 增加 Wi-Fi promiscuous mode
6. 做 Beacon parser
7. 做 channel hopper
8. 建 AP DB
9. 建 STA DB
10. 加 EAPOL detector
11. 加 PCAP logger
12. 再开始 Epoch / Personality / UI

关键判断点：

**Phase 1 能稳定跑通后，项目的主要技术路线风险就基本消失。**
