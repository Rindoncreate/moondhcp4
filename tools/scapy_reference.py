"""Independent Scapy wire construction and parsing, never imports our codec.

Scapy does not provide our strict-profile or RFC3396 acceptance verdicts.
Those are checked against the explicit normative partitions separately.
"""
from pathlib import Path
from importlib.metadata import version
import json
from scapy.layers.dhcp import BOOTP, DHCP
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap, rdpcap

ROOT=Path(__file__).resolve().parents[1]


def main():
    assert version('scapy')=='2.6.1'
    fixtures=json.loads((ROOT/'fixtures/wire.json').read_text(encoding='utf8'))['cases']
    parsed=0
    for case in fixtures:
        if case['expectedCode']!=0:
            continue
        data=bytes.fromhex(case['hex'])
        packet=BOOTP(data)
        assert packet.xid==0xffffffff,case['name']
        assert bytes(packet)==data,case['name']
        assert DHCP in packet,case['name']
        parsed+=1
    independently_constructed=[]
    for kind in range(1,9):
        packet=BOOTP(op=2 if kind in (2,5,6) else 1,htype=1,hlen=6,xid=0xffffffff,
                     chaddr=bytes.fromhex('020000000001'))/DHCP(options=[('message-type',kind),'end'])
        wire=bytes(packet).ljust(300,b'\0')
        expected=next(c for c in fixtures if c['name']==f'message-{kind}')
        assert wire.hex()==expected['hex'],kind
        independently_constructed.append({'name':f'scapy-message-{kind}','hex':wire.hex()})
    output=ROOT/'_build'
    output.mkdir(exist_ok=True)
    (output/'scapy-generated.json').write_text(json.dumps(independently_constructed,indent=2)+'\n',encoding='utf8')
    capture=Ether(src='02:00:00:00:00:01',dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0',dst='255.255.255.255')/UDP(sport=68,dport=67)/BOOTP(bytes.fromhex(fixtures[0]['hex']))
    capture.time=0
    wrpcap(str(output/'synthetic-discover.pcap'),[capture])
    extracted=bytes(rdpcap(str(output/'synthetic-discover.pcap'))[0][BOOTP])
    assert extracted.hex()==fixtures[0]['hex']
    (output/'extracted-discover.bin').write_bytes(extracted)
    (output/'scapy-report.json').write_text(json.dumps({'scapyVersion':version('scapy'),'positivePacketsParsedAndReserialized':parsed,'independentlyConstructedMessages':8,'pcapPayloadsExtracted':1,'note':'Not a full protocol conformance or independent acceptance agreement claim'},indent=2)+'\n',encoding='utf8')
    print(f'Scapy independently constructed 8 messages; parsed/reserialized {parsed} positive wire fixtures; extracted 1 PCAP payload')


if __name__=='__main__':main()
