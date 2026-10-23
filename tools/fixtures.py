"""Deterministic handwritten wire partitions, encoded with Python stdlib struct.

These are specified expectations, not results obtained from MoonBit or Scapy.
Scapy independently constructs/checks selected packets in scapy_reference.py.
"""
from pathlib import Path
import json
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
MAC = bytes.fromhex('020000000001')


def tlv(code, data):
    return bytes([code, len(data)]) + data


def area(items):
    return b''.join(tlv(k, v) for k, v in items) + b'\xff'


def packet(kind=1, extra=(), file=b'', sname=b'', mask=0, main=None, xid=0xFFFFFFFF, op=None, pad=True):
    if op is None:
        op = 2 if kind in (2, 5, 6) else 1
    options = [(53, bytes([kind]))]
    if mask:
        options.append((52, bytes([mask])))
    options.extend(extra)
    header = struct.pack('!BBBBIHH4s4s4s4s16s64s128s', op, 1, 6, 0, xid, 0, 0,
                         b'\0'*4, b'\0'*4, b'\0'*4, b'\0'*4, MAC.ljust(16, b'\0'),
                         sname.ljust(64, b'\0'), file.ljust(128, b'\0'))
    data = header + bytes.fromhex('63825363') + (area(options) if main is None else main)
    return data.ljust(300, b'\0') if pad else data


def cases():
    out = []
    def add(name, data, code=0, logical=None):
        out.append({'name':name, 'hex':data.hex(), 'expectedCode':code,
                    'logical':{str(k):v.hex() for k,v in (logical or {}).items()}})
    for kind in range(1,9):
        add(f'message-{kind}', packet(kind), logical={53:bytes([kind])})
    add('minimum-unpadded', packet(pad=False))
    add('unknown-zero-length', packet(extra=[(224,b'')]), logical={224:b''})
    add('unknown-binary', packet(extra=[(223,b'\xff\x00\x80')]), logical={223:b'\xff\x00\x80'})
    add('lease-reassembled-before-width-check', packet(extra=[(51,b'\xff'),(51,b'\xff\xff\xff')]), logical={51:b'\xff'*4})
    add('long-fragments', packet(extra=[(222,b'x'*255),(222,b'x'*255),(222,b'x'*90)]), logical={222:b'x'*600})
    add('file-overload', packet(2, extra=[(200,b'A')], mask=1, file=area([(200,b'B')])), logical={200:b'AB'})
    add('sname-overload', packet(2, extra=[(200,b'A')], mask=2, sname=area([(200,b'C')])), logical={200:b'AC'})
    add('aggregate-order-not-wire-order', packet(2, extra=[(200,b'A')], mask=3, file=area([(200,b'B')]), sname=area([(200,b'C')])), logical={200:b'ABC'})
    add('typed-option-split-at-unaligned-byte', packet(2, extra=[(6,b'\xc0')], mask=1, file=area([(6,b'\x00\x02\x01')])), logical={6:bytes.fromhex('c0000201')})
    add('opaque-inactive-fields', packet(file=b'not-an-option\xff',sname=b'\xff\xfe'), logical={53:b'\x01'})
    add('pad-between-options', packet(main=b'\x00\x35\x01\x01\x00\xc8\x01A\xff'), logical={200:b'A'})
    add('complete-address-options',packet(5,extra=[(1,bytes.fromhex('ffffff00')),(3,bytes.fromhex('c0000201')),(6,bytes.fromhex('c0000235c0000236')),(51,bytes.fromhex('00000e10')),(54,bytes.fromhex('c0000201')),(57,bytes.fromhex('0240'))]))
    for name,data in [('empty',b''),('short',packet()[:239]),('no-cookie',packet()[:236]+b'xxxx'+packet()[240:]),('invalid-op',b'\x00'+packet()[1:]),('invalid-hlen',packet()[:2]+b'\x11'+packet()[3:])]:
        add(name,data,2)
    add('no-main-end',packet(main=b'\x35\x01\x01',pad=False),2)
    add('no-tlv-length',packet(main=b'\x35\x01\x01\xc8',pad=False),2)
    add('tlv-crosses-main-end',packet(main=b'\x35\x01\x01\xc8\x04ab',pad=False),2)
    add('strict-profile-non-pad-after-end',packet(main=b'\x35\x01\x01\xffX'),2)
    add('overload-invalid-mask',packet(extra=[(52,b'\x04')]),2)
    add('overload-empty',packet(extra=[(52,b'')]),2)
    add('overload-repeated-nonempty',packet(extra=[(52,b'\x01'),(52,b'\x01')]),2)
    add('overload-empty-fragment-concatenates',packet(2,extra=[(52,b''),(52,b'\x01')],file=area([])))
    add('overload-file-no-end',packet(2,mask=1,file=b'\0'*128),2)
    add('overload-sname-no-end',packet(2,mask=2,sname=b'\0'*64),2)
    add('overload-file-crosses-boundary',packet(2,mask=1,file=b'\xc8\x7f'+b'a'*126),2)
    add('nested-overload-rejected',packet(2,mask=1,file=area([(52,b'\x01')])),2)
    add('missing-message-type',packet(main=b'\xff'),1)
    add('unknown-message-type',packet(9),1)
    add('message-type-too-long',packet(extra=[(53,b'\x01')]),1)
    add('reply-with-request-op',packet(5,op=1),1)
    for code,value in [(1,b'123'),(3,b'12345'),(6,b''),(12,b''),(15,b''),(50,b'123'),(51,b'123'),(54,b'123'),(55,b''),(57,b'\x02\x3f'),(58,b'123'),(59,b'123'),(60,b''),(61,b'x')]:
        add(f'invalid-option-{code}',packet(extra=[(code,value)]),1)
    return out


def generate(check=False):
    rows=cases()
    payload=json.dumps({'format':'handwritten-RFC-partitions-v1','cases':rows},indent=2)+'\n'
    lines=['///|','// Generated from tools/fixtures.py; expectations are independent of MoonBit.','test "independent handwritten wire partitions" {','  let cases : Array[(String, String, Int, Array[(Int, String)])] = [']
    for row in rows:
        logical=', '.join(f'({k}, {json.dumps(v)})' for k,v in row['logical'].items())
        lines.append(f'    ({json.dumps(row["name"])}, {json.dumps(row["hex"])}, {row["expectedCode"]}, [{logical}]),')
    lines.extend(['  ]','  for (name, hex, expected, logical) in cases {','    let actual = try {','      let packet = @moondhcp4.decode(@moondhcp4.from_hex(hex))','      for (code, value) in logical {','        assert_eq(packet.option(code), Some(@moondhcp4.from_hex(value)))','      }','      if packet.diagnose().any(i => i.severity == "error") { 1 } else { 0 }','    } catch {','      @moondhcp4.Malformed(_, _) | @moondhcp4.InvalidModel(_) => 2','      @moondhcp4.Limit(_) => 4','      error => fail("\\{name}: unexpected test error \\{error}")','    }','    if actual != expected {','      fail("\\{name}: expected \\{expected}, got \\{actual}")','    }','  }','}',''])
    outputs={ROOT/'fixtures/wire.json':payload,ROOT/'reference_test.mbt':'\n'.join(lines)}
    for path,content in outputs.items():
        if check:
            if path.suffix == '.mbt':
                continue # The compiler formatter owns layout; CI regenerates it.
            if path.read_text(encoding='utf8').replace('\r\n','\n') != content:
                raise SystemExit(f'fixture drift: {path.name}; regenerate then format')
        else:
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(content,encoding='utf8',newline='\n')
    return len(rows)


if __name__ == '__main__':
    print(f'Generated {generate("--check" in sys.argv)} specified wire partitions')
