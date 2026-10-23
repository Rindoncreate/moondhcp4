from pathlib import Path
from scapy.layers.dhcp import BOOTP,DHCP
root=Path(__file__).resolve().parents[1]
for name,kind in [('discover',1),('offer',2)]:
    wire=(root/f'_build/{name}-built.bin').read_bytes()
    packet=BOOTP(wire)
    options=dict(v for v in packet[DHCP].options if isinstance(v,tuple))
    assert options['message-type']==kind
    assert packet.xid==0xffffffff
    if name=='offer':
        assert packet.yiaddr=='192.0.2.10'
        assert options['lease_time']==3600
        assert options['server_id']=='192.0.2.1'
    assert bytes(packet)==wire
print('Scapy independently read both MoonBit-built DISCOVER and OFFER files')
