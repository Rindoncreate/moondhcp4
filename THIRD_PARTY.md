# Attribution and test-data provenance

- Rindoncreate is the original author, with AI assistance, under MIT. Core codec,
  reassembly, diagnostics, typed accessors and the bridge are newly written.
- MoonBit core supplies standard data structures/debug/JSON/string functions,
  under Apache-2.0. No third-party protocol runtime is required.
- RFC 2131, RFC 2132 and RFC 3396 are specification references. No RFC grammar,
  implementation source or diagrams are copied into the library.
- Scapy 2.6.1 is a GPL-2.0-only development dependency, obtained from PyPI. It
  runs separately to construct/parse test packets. No Scapy source is copied or
  linked into MoonBit production code. Reference: https://github.com/secdev/scapy
- Handwritten Python struct encodings and expected outcomes are project-owned
  fixtures. The synthetic PCAP is generated from those new packets, with a local
  MAC and documentation-range IP addresses. There is no private traffic capture.
- Prior pet/PetGrowth, MoonSchedule and MoonCDDL source and histories are not
  incorporated. Using the same generic development tools is not counted as new
  protocol functionality.

Scapy results are not described as complete independent DHCP acceptance verdicts.
RFC3396 order, resource limits and strict-profile rejection policies have their
own specified fixtures. See docs/verification.md for what was actually run.
