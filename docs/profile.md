# DHCPv4 wire profile v1

This is an embeddable **UDP payload codec**, not a DHCP service or complete
state-machine conformance verifier. Core library packages have no host FFI,
filesystem, sockets or external runtime dependency. `bridge` is JS-only for the
Node filesystem CLI; portable core tests also execute on native/Wasm/Wasm-GC.

## Supported contract

| Area | Behavior | Evidence |
| --- | --- | --- |
| Header | Exact BOOTP field sizes and network byte order; op 1/2; hlen 0..16; full UInt32 xid | eight message types, xid=0xffffffff, truncated headers |
| Fields | ciaddr/yiaddr/siaddr/giaddr and opaque 16/64/128-byte fields | inactive binary file/sname fixtures; fixed-length checks |
| Framing | Cookie, Pad, End, checked TLV lengths; no fragment crosses a physical area | cookie, truncated TLV, missing End, overload boundary fixtures |
| Overload | Main option 52 selects file/sname; parse only active regions | file-only/sname-only/both/empty regions |
| Reassembly | Concatenate before interpreting values, in main → file → sname order | distinct A/B/C fragments and a DNS address split at an unaligned byte |
| Encoding | Canonical Pad/framing, fragment order retained within each area; fields marked active rebuilt from options; inactive fields retained | idempotence, cross-implementation output parsing |
| Typed access | Four-byte UInt32 and IPv4 lists from logical option values | unsigned infinite lease and multiple DNS addresses |
| Diagnosis | Message type 1..8 and op, selected option lengths/minima, reserved-flag warning | negative semantic fixtures; diagnostic exit code distinct from malformed wire |

Strict receiver-profile restrictions: active areas require End; bytes after End
must be Pad; an overload marker outside the main area is rejected. The main-area
Pad restriction is stricter than the recommendation for ordinary non-overloaded
messages. These choices are explicit acceptance boundaries, not claims that all
other DHCP tools must reject the same data. A newer/unknown DHCP message type can
be decoded structurally but is outside the classic 1..8 diagnostic profile.

Overload control fragments in main are reassembled before its one-byte length is
checked. Two nonempty copies produce an invalid logical length; an empty fragment
followed by its one-byte value is accepted. No per-fragment primitive-length test
is used to defeat RFC 3396 reassembly.

There is no automatic overload packing. A programmatic caller selects physical
areas and option 52; mismatches are explicit model errors. `split_option` makes
fragmentation an explicit caller decision and does not negotiate peer support.

## Boundaries

- No bare BOOTP without a DHCP cookie, DHCPv6, IP/UDP checksum or packet capture.
- No sockets, leases, address allocation, renewal state machine or OS networking.
- Not every IANA option is typed; unknown codes 1..254 remain raw bytes. Options
  0/255 are framing, not RawOption objects. Unknown vendor-specific values remain
  opaque, not falsely labelled semantically validated.
- Diagnostics do not prove all message-specific mandatory/forbidden options,
  server behavior, timer relations, authenticity or network acceptance.
- Encoding is semantic/canonical, not byte-lossless. Padding and active field
  encodings may change. Raw inactive sname/file fields remain unchanged.
- Packet and option arrays are caller-owned; callers must not mutate them during
  an operation. `diagnose` is designed for a structurally decoded packet; call
  `encode` to validate fixed-width fields of a programmatic model.

## Limits and errors

The profile accepts at most 65,507 payload bytes and 4,096 TLV fragments, before
allocating/copying large values. A fragment has at most 255 value bytes. File and
sname have fixed capacities 128/64, including End. Canonical output is padded to
at least 300 payload bytes. Receivers accept shorter structurally valid payloads.

Decode/model/limit failures are checked `DhcpError` values, not panic-based input
control. CLI codes: 0 success under this profile; 1 semantic diagnostics; 2
malformed wire or invalid builder model; 3 file/host failure; 4 resource bound;
64 invocation/build setup. Code 0 is not an assertion that a real DHCP server or
client will accept a message in its current state.

Builder config has a 131,014 UTF-16-unit / CLI-byte bound and pre-parsing nesting
limit 32. Integer config values are decimal **strings** to avoid floating-point
JSON rounding. IPv4 fields use dotted decimal strings. Config object duplicates
follow the standard parser's last-value mapping; this authoring format is not a
signed or lossless JSON interchange format. Unknown config fields fail.

## Specification map

- [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html): header, op, option areas.
- [RFC 2132](https://www.rfc-editor.org/rfc/rfc2132.html): TLV, selected options.
- [RFC 3396](https://www.rfc-editor.org/rfc/rfc3396.html): fragment aggregation.

These are implemented scopes, not a statement that every requirement of those
documents and every later update is implemented.
