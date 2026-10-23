# Topic and overlap check

Direction: new, original MoonBit ecosystem package; not the prior application
or a maintenance contribution to someone else's project.

Official registry metadata snapshot on 2026-10-22:
`8f54a7a67775276110c310ae9bacfc2be5d4bc92`, obtained from
https://mooncakes.io/git/index . Module names, descriptions and keywords, including
historical rows, had no `dhcp` or `bootp` match. This is bounded search evidence,
not proof that no unpublished or internally implemented related code exists.

Related infrastructure was also inspected: cghyyrrt/moonbit-pcap documents many
capture/network protocols but does not list DHCP; usagi-star/mooncap is another
capture parser. These are potential byte suppliers rather than a reason to
reimplement capture readers. Existing generic UDP/binary libraries likewise do
not by themselves establish duplicate DHCP option aggregation functionality.

The independently written increment is the reusable BOOTP/DHCPv4 payload model,
checked TLV/overload codec, logical RFC3396 aggregation, typed value access,
diagnostics and file consumers. There is no UI/storage complexity being counted
as protocol implementation. Demand is explained through capture analysis,
protocol generation and simulated-device fixtures, each with a concrete test.

No initial-review approval or external adoption is claimed. The formal proposal
must explain practical consumers and the supported scope, using the official
template. This document is AI-assisted technical evidence, not a manually authored
application statement.
