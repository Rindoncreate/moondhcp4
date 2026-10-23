# Complete expected consumer scenarios

These are expected workflows with reproducible local test counterparts, not
claims of existing external users, maintainers' approval or production adoption.

## Capture-analysis pipeline

A network tool already has PCAP/IP/UDP parsing. It extracts a DHCP UDP payload
and calls `decode`, `option`, the typed accessors and `diagnose`. It obtains
addresses, logical option bytes and a bounded error/diagnostic report. Malformed
TLVs stop with a byte offset; unknown options can still be retained for analysis.

The acceptance counterpart constructs a synthetic PCAP with Scapy, reads that
capture independently, extracts its BOOTP/DHCP payload and passes the real binary
file to the Node CLI. Scapy handles capture framing; this project does not claim
to implement or replace a PCAP reader. Existing MoonBit capture libraries can
supply the same byte boundary.

## Client/protocol test-data generation

A test author prepares `examples/discover.json`, calls the file CLI `build`,
and obtains a binary DISCOVER with a specified transaction ID, MAC and request
list. Scapy independently decodes the emitted bytes and verifies its fields.
The same library API can generate REQUEST, RELEASE and INFORM payloads without
embedding a Node/Python protocol implementation in a MoonBit client.

## Simulated device/server reply fixtures

A test harness chooses a transaction ID and offered address and builds the
`examples/offer.json` reply. The output carries router/DNS/server/lease options
and can be replayed in a device integration test. Independent Scapy decoding
checks the address, full unsigned ID, server ID and lease. No address is actually
allocated by this project. Overloaded or fragmented responses can be represented
at the library boundary and are covered by explicit reassembly tests.

## CLI reproduction

After `moon build --target js`, use fresh output paths:

```sh
node bin/moondhcp4.mjs build examples/discover.json discover.bin --json
node bin/moondhcp4.mjs inspect discover.bin --json
node bin/moondhcp4.mjs normalize discover.bin normalized.bin --json
node bin/moondhcp4.mjs build examples/offer.json offer.bin --json
```

Output files are created only. An existing output is an explicit host failure;
use a new path instead of overwriting input or an earlier artifact.
