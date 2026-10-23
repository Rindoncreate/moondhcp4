# Public API

Import `Rindoncreate/moondhcp4`. There are no external protocol runtime imports.
The generated `pkg.generated.mbti` records the checked public interface.

| API | Contract |
| --- | --- |
| `Packet::new(type, xid, hardware)` | Ethernet constructor; type 1..8, six address bytes; no I/O |
| `decode(Bytes)` | UDP payload → checked Packet; malformed bytes and limits raise DhcpError |
| `encode(Packet)` | Validate model and emit canonical payload; refuses physical-area overflow |
| `packet.option(code)` | Missing → None; otherwise reassembled immutable bytes |
| `packet.message_type()` | One-byte type value when present; diagnose checks profile range |
| `packet.u32_option(code)` | None or full UInt32; raises on wrong logical length |
| `packet.ipv4_list_option(code)` | None or byte-address array; raises on invalid logical list |
| `packet.diagnose()` | Selected semantic Issues; no complete state-machine guarantee |
| `split_option(code, data, area)` | Explicit ≤255-byte fragments; no automatic peer negotiation |
| `from_hex` / `to_hex` | Bounded file/FFI conversion helpers |

Packet stores physical `RawOption` fragments and a fixed-width Header. Main/file/
sname areas are explicit. Do not treat its mutable arrays as a concurrent shared
snapshot; callers control ownership. Do not infer UTF-8 from opaque wire values.

Byte offsets in Malformed refer to the input UDP payload. `InvalidModel` reports
invalid programmatic/builder values; `Limit` is distinct from a protocol mismatch.

The Node bridge accepts `inspect`, `normalize` and `build`. It serializes the
MoonBit result. The Node host only handles files, UTF-8/hex transport and exit
codes. Unknown options are visible through raw and logical option lists rather
than being silently dropped.
