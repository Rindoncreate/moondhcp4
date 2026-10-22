# MoonDHCP4

MoonBit 原生 DHCPv4 报文编解码、选项重组与结构诊断库。独立新项目，MIT，作者 Rindoncreate；代码与技术文档含 AI 辅助。

状态：开发与验证中，未发布 Mooncakes、未申报或通过赛事初审。不能将仓库存在视为交付验收完成。

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

独立对照、真实文件 CLI、支持矩阵与赛事核对材料正在随实现补齐。正式申报书需要按官方模板由作者人工撰写，本 README 不冒充人工稿。

## 标准与归属

依据 [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html)、[RFC 2132](https://www.rfc-editor.org/rfc/rfc2132.html)、[RFC 3396](https://www.rfc-editor.org/rfc/rfc3396.html) 原创实现。未复制其他协议实现源码。此前宠物产品、MoonSchedule 与 MoonCDDL 的代码与提交均不计入本项目。
