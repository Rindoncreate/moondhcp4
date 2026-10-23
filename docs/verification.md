# Executed verification record

Verified source: `6893de725be60b395e37fa2470412f9233b7a809`.
[Successful complete CI run 39958845130](https://github.com/Rindoncreate/moondhcp4/actions/runs/39958845130)
on 2026-10-23. Linux compiler: `moonc v0.10.17+d971670cd`; installed skill
references are pinned to 0.10.14, so actual execution is the evidence.

## Passed remotely

- Formatting and generated-fixture drift checks; public API manifest drift check.
- Check/build/test with warnings denied on JS, Wasm, Wasm GC and Linux native.
  Each backend reports **10 test blocks**, one containing 55 handwritten wire
  partitions. These numbers are not added to claim 65 tests or a coverage rate.
- Node bridge repeats all 55 specified outcomes and checks logical option values
  and canonical normalization idempotence for the positive cases.
- Scapy 2.6.1 independently constructs eight message types; parses and reserializes
  21 positive fixtures; extracts one synthetic PCAP payload; and independently
  reads both MoonBit-built DISCOVER/OFFER binary outputs.
- 1,500 deterministic truncation/mutation inputs return bounded results without
  uncaught failure. This is robustness evidence, not 1,500 correctness assertions,
  a full fuzzer campaign, or proof of complete RFC compatibility.
- Actual-file CLI: build, inspect, normalize, PCAP payload, malformed input,
  semantic diagnosis, nonexistent file, invalid invocation and refusal to
  overwrite an existing output.
- `moon package` creates a source archive. A fresh temporary workspace extracts
  that archive and compiles a separate public-API consumer. JS/native each report
  11 blocks across the workspace (10 library blocks plus one consumer block).
  This is source-package consumption, **not a registry installation**.

Scapy does not implement our full diagnostic verdict or automatic RFC3396
aggregation. Those expectations remain explicitly handwritten normative/profile
partitions. No 55/55 independent acceptance agreement, complete IANA option
validation, standards certification, throughput result or external adoption is
claimed.

## Local Windows boundary

The local application-control policy blocks starting `moon.exe`; this turn did
not recompile MoonBit locally and did not bypass that policy. Previously recorded
local version was 0.10.15, not a version newly confirmed this turn. Remote build
output was obtained from the verified job's public-code export for inspection.
The exported Node CLI has been exercised locally to build and inspect a binary
DISCOVER with xid 4294967295. A full local Scapy pipeline was not run.

One local Scapy installation approval timed out; the sandboxed installation
could not access PyPI. Scapy installation and independent comparisons succeeded
on the CI runner instead. The complete source reproduction commands require a
normally functioning compiler and the pinned test dependencies.

## Retained failures and corrections

- Run 39956047644 did not start jobs: an unquoted YAML scalar contained the
  `--only-binary=:all:` argument. A block scalar corrected it.
- Run 39958239641 caught an unused dependency in the separate consumer under
  `--deny-warn`. The consumer now actually calls the dependency from its public
  library function. Warnings were not disabled and targets were not removed.

## Not completed

No Mooncakes publication or separate registry-consumer install, formal MoonDHCP4
application, initial-review approval or production deployment exists in this
record. Formal application authorship and the official template remain separate
from these AI-assisted technical facts. A successful CI does not substitute for
those deliverables.
