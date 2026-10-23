# MoonDHCP4

MoonBit 原生 DHCPv4 报文编解码、选项重组与结构诊断库。独立新项目，MIT，作者 Rindoncreate；代码与技术文档含 AI 辅助。

状态：首版已实现，正在完成交付核对。尚未发布 Mooncakes、未申报或通过赛事初审。实际验证记录见 [docs/verification.md](docs/verification.md)；不能将仓库存在视为交付验收完成。

核心 API 面向 UDP **负载**，不含 Ethernet/IP/UDP 头。可为已有抓包工具、协议测试与模拟设备提供数据层；不提供完整 DHCP 服务、地址池、系统网络配置或 DHCPv6。

## 范围

- BOOTP 固定头、DHCP cookie、Pad/End/TLV 编解码。
- RFC 2132 option 52 的 file/sname overload。
- RFC 3396 跨区分片重组，严格采用 main → file → sname 顺序。
- 未知选项与非 UTF-8 原始字段保留；完整 UInt32 xid/计时字段不会经有符号 Int 截断。
- 已声明选项的逻辑长度、消息类型/op 一致性等诊断；不是完整 DHCP 状态机合规证明。
- 编码规范化 Pad 与分片位置，不承诺线缆字节级无损往返。显式分片，不猜测对端是否支持长选项。

## 最小示例

```moonbit
let packet = @moondhcp4.Packet::new(1, 0xffffffffU, b"\x02\x00\x00\x00\x00\x01")
let wire = @moondhcp4.encode(packet)
let decoded = @moondhcp4.decode(wire)
assert_eq(decoded.message_type(), Some(1))
assert_true(decoded.diagnose().is_empty())
```

```sh
moon check --target js --deny-warn
moon test --target js --deny-warn
```

## 源码安装和文件 CLI

需要可正常运行的 MoonBit stable 工具链与 Node.js 22+。当前未发布注册表，请从源码构建，不要假设 `moon add` 已可安装：

```sh
git clone https://github.com/Rindoncreate/moondhcp4.git
cd moondhcp4
moon build --target js --deny-warn
node bin/moondhcp4.mjs build examples/discover.json discover.bin --json
node bin/moondhcp4.mjs inspect discover.bin --json
node bin/moondhcp4.mjs normalize discover.bin normalized.bin --json
node bin/moondhcp4.mjs build examples/offer.json offer.bin --json
```

CLI 读取真实文件；输出路径必须尚不存在。Node 负责文件 I/O 和文本/hex 传输，协议编解码、JSON 配置解释和结果诊断均由 MoonBit 执行。返回码 0 表示符合已声明 profile，1 为诊断错误，2 为报文/模型错误，3 为文件错误，4 为资源限制，64 为命令或构建设置错误。

配置中的 messageType、xid、option code 使用十进制字符串，地址使用点分十进制，选项值为 hex。这样保留完整 UInt32 域并避免 JSON 浮点舍入；示例 MAC 与地址均为合成测试数据。

## 验证

Scapy 2.6.1 仅作开发期独立参照，不进入运行时依赖。

```sh
python -m venv .venv
# Windows 用 .venv/Scripts/python.exe；以下为 Linux/macOS 路径
.venv/bin/python -m pip install --only-binary=:all: -r tools/requirements.txt
PYTHON=.venv/bin/python MOON_NATIVE=1 node tools/verify.mjs
```

Windows PowerShell 可先使用 `.venv/Scripts/python.exe` 安装依赖，然后执行 `node tools/verify.mjs`；Linux CI 另外检查 native。系统应用控制若阻止 MoonBit 编译器，需要通过正常工具链环境或远端 CI 构建；本项目不修改系统安全策略。

测试区分三类证据：规范手工样本、Scapy 独立构造/读取、健壮性变异输入。不会把所有手工预期算成独立对照一致，也不把无崩溃样本计为标准覆盖率。独立消费者在临时 workspace 中使用打包后的源码；这不等于已从 Mooncakes 安装。

## 用途和边界

1. 抓包分析工具将已提取的 UDP 负载交给本库，读取 DHCP 地址/选项与诊断。
2. 协议测试工具构造 DISCOVER/REQUEST 等负载，由其他实现独立解析验证。
3. 模拟设备测试构造 OFFER/ACK 回复文件，保留 transaction ID、服务器与租期等字段。

这些是预期消费场景，不冒充外部采用。完整流程见 [scenarios](docs/scenarios.md)，接口见 [API](docs/api.md)，标准/限制见 [profile](docs/profile.md)，查重见 [selection](docs/selection.md)，归属见 [THIRD_PARTY](THIRD_PARTY.md)。

正式申报书需要按官方模板由作者人工撰写；README 与技术参考材料不冒充人工稿。

## 标准与归属

依据 [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html)、[RFC 2132](https://www.rfc-editor.org/rfc/rfc2132.html)、[RFC 3396](https://www.rfc-editor.org/rfc/rfc3396.html) 原创实现。未复制其他协议实现源码。此前宠物产品、MoonSchedule 与 MoonCDDL 的代码与提交均不计入本项目。
