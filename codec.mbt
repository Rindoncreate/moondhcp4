///|
fn read16(data : Bytes, offset : Int) -> Int {
  data[offset].to_int() * 256 + data[offset + 1].to_int()
}

///|
fn read32(data : Bytes, offset : Int) -> UInt {
  (data[offset].to_uint() << 24) |
  (data[offset + 1].to_uint() << 16) |
  (data[offset + 2].to_uint() << 8) |
  data[offset + 3].to_uint()
}

///|
fn parse_area(data : Bytes, start : Int, end : Int, area : Area, output : Array[RawOption]) -> Unit raise DhcpError {
  let mut offset = start
  while offset < end {
    let at = offset
    let code = data[offset].to_int()
    offset = offset + 1
    if code == 0 {
      continue
    }
    if code == 255 {
      while offset < end {
        if data[offset] != 0 {
          raise Malformed(offset, "only Pad bytes may follow End within an option area")
        }
        offset = offset + 1
      }
      return
    }
    if offset >= end {
      raise Malformed(at, "option code has no length byte")
    }
    let length = data[offset].to_int()
    offset = offset + 1
    if length > end - offset {
      raise Malformed(at, "option value crosses its physical area boundary")
    }
    output.push({ code, data: data[offset:offset + length].to_owned(), area })
    if output.length() > 4096 {
      raise Limit("packet has more than 4096 TLV fragments")
    }
    offset = offset + length
  }
  raise Malformed(end, "active option area has no End marker")
}

///|
fn overload(options : Array[RawOption]) -> Int raise DhcpError {
  let data : Array[Byte] = []
  let mut seen = false
  for fragment in options {
    if fragment.code == 52 {
      if fragment.area != Main {
        raise InvalidModel("option 52 must occur in the main option area")
      }
      for byte in fragment.data {
        data.push(byte)
      }
      seen = true
    }
  }
  if !seen {
    return 0
  }
  if data.length() != 1 {
    raise InvalidModel("reassembled option 52 must have one byte")
  }
  let value = data[0].to_int()
  if value < 1 || value > 3 {
    raise InvalidModel("option 52 value must be 1, 2 or 3")
  }
  value
}

///|
/// Decode a bounded DHCPv4 UDP payload. Structural decoding is distinct from
/// semantic diagnostics: call Packet::diagnose before accepting a message.
pub fn decode(data : Bytes) -> Packet raise DhcpError {
  if data.length() > 65507 {
    raise Limit("DHCP payload exceeds 65507 bytes")
  }
  if data.length() < 240 {
    raise Malformed(data.length(), "DHCP payload needs a 236-byte header and cookie")
  }
  if data[236:240] != b"\x63\x82\x53\x63"[:] {
    raise Malformed(236, "missing DHCP magic cookie")
  }
  if data[0] != 1 && data[0] != 2 {
    raise Malformed(0, "op must be BOOTREQUEST or BOOTREPLY")
  }
  if data[2] > 16 {
    raise Malformed(2, "hardware address length exceeds chaddr")
  }
  let header : Header = {
    op: data[0].to_int(), htype: data[1].to_int(), hlen: data[2].to_int(), hops: data[3].to_int(),
    xid: read32(data, 4), secs: read16(data, 8), flags: read16(data, 10),
    ciaddr: data[12:16].to_owned(), yiaddr: data[16:20].to_owned(),
    siaddr: data[20:24].to_owned(), giaddr: data[24:28].to_owned(),
    chaddr: data[28:44].to_owned(), sname: data[44:108].to_owned(), file: data[108:236].to_owned(),
  }
  let options : Array[RawOption] = []
  parse_area(data, 240, data.length(), Main, options)
  let mask = overload(options)
  if (mask & 1) != 0 {
    parse_area(data, 108, 236, BootFile, options)
  }
  if (mask & 2) != 0 {
    parse_area(data, 44, 108, ServerName, options)
  }
  ignore(overload(options))
  { header, options }
}

///|
fn check_range(value : Int, maximum : Int, name : String) -> Unit raise DhcpError {
  if value < 0 || value > maximum {
    raise InvalidModel(name + " outside its wire range")
  }
}

///|
fn check_length(value : Bytes, length : Int, name : String) -> Unit raise DhcpError {
  if value.length() != length {
    raise InvalidModel(name + " has an invalid fixed length")
  }
}

///|
fn append_bytes(output : Array[Byte], value : Bytes) -> Unit {
  for b in value {
    output.push(b)
  }
}

///|
fn write16(output : Array[Byte], value : Int) -> Unit {
  output.push((value >> 8).to_byte())
  output.push((value & 255).to_byte())
}

///|
fn write32(output : Array[Byte], value : UInt) -> Unit {
  output.push((value >> 24).to_byte())
  output.push(((value >> 16) & 255).to_byte())
  output.push(((value >> 8) & 255).to_byte())
  output.push((value & 255).to_byte())
}

///|
fn encode_area(options : Array[RawOption], area : Area, capacity : Int) -> Bytes raise DhcpError {
  let output : Array[Byte] = []
  for fragment in options {
    if fragment.area == area {
      if fragment.code < 1 || fragment.code > 254 || fragment.data.length() > 255 {
        raise InvalidModel("TLV code must be 1..254 and fragment length at most 255")
      }
      if output.length() + fragment.data.length() + 3 > capacity {
        raise Limit("options and End do not fit in their physical area")
      }
      output.push(fragment.code.to_byte())
      output.push(fragment.data.length().to_byte())
      append_bytes(output, fragment.data)
    }
  }
  output.push(255)
  if area != Main {
    while output.length() < capacity {
      output.push(0)
    }
  }
  Bytes::from_array(output)
}

///|
/// Encode a canonical payload. Pads/fragment locations within each area are
/// normalized; inactive opaque header fields are retained. Not byte-lossless.
/// No automatic overload allocation or peer-capability assumption is made.
pub fn encode(packet : Packet) -> Bytes raise DhcpError {
  let h = packet.header
  if h.op != 1 && h.op != 2 {
    raise InvalidModel("op must be BOOTREQUEST or BOOTREPLY")
  }
  check_range(h.htype, 255, "htype")
  check_range(h.hlen, 16, "hlen")
  check_range(h.hops, 255, "hops")
  check_range(h.secs, 65535, "secs")
  check_range(h.flags, 65535, "flags")
  check_length(h.ciaddr, 4, "ciaddr")
  check_length(h.yiaddr, 4, "yiaddr")
  check_length(h.siaddr, 4, "siaddr")
  check_length(h.giaddr, 4, "giaddr")
  check_length(h.chaddr, 16, "chaddr")
  check_length(h.sname, 64, "sname")
  check_length(h.file, 128, "file")
  if packet.options.length() > 4096 {
    raise Limit("packet has more than 4096 TLV fragments")
  }
  let mask = overload(packet.options)
  for fragment in packet.options {
    if (fragment.area == BootFile && (mask & 1) == 0) ||
       (fragment.area == ServerName && (mask & 2) == 0) {
      raise InvalidModel("non-main options require the corresponding option 52 bit")
    }
  }
  let file = if (mask & 1) != 0 { encode_area(packet.options, BootFile, 128) } else { h.file }
  let sname = if (mask & 2) != 0 { encode_area(packet.options, ServerName, 64) } else { h.sname }
  let main = encode_area(packet.options, Main, 65507 - 240)
  let output : Array[Byte] = [h.op.to_byte(), h.htype.to_byte(), h.hlen.to_byte(), h.hops.to_byte()]
  write32(output, h.xid)
  write16(output, h.secs)
  write16(output, h.flags)
  for bytes in [h.ciaddr, h.yiaddr, h.siaddr, h.giaddr, h.chaddr, sname, file] {
    append_bytes(output, bytes)
  }
  append_bytes(output, b"\x63\x82\x53\x63")
  append_bytes(output, main)
  while output.length() < 300 {
    output.push(0)
  }
  Bytes::from_array(output)
}

///|
/// Parse hex only at the file/FFI boundary; offsets are byte offsets everywhere
/// in the wire codec, and UTF-16 indices only in malformed hex diagnostics.
pub fn from_hex(text : String) -> Bytes raise DhcpError {
  if text.length() > 131014 {
    raise Limit("hex payload exceeds 65507 bytes")
  }
  if text.length() % 2 != 0 {
    raise InvalidModel("hex input must have an even number of digits")
  }
  fn digit(c : UInt16) -> Int raise DhcpError {
    if c >= '0' && c <= '9' { c.to_int() - 48 }
    else if c >= 'a' && c <= 'f' { c.to_int() - 87 }
    else if c >= 'A' && c <= 'F' { c.to_int() - 55 }
    else { raise InvalidModel("hex input contains a non-hex character") }
  }
  let output : Array[Byte] = []
  for i = 0; i < text.length(); i = i + 2 {
    output.push((digit(text[i]) * 16 + digit(text[i + 1])).to_byte())
  }
  Bytes::from_array(output)
}

///|
pub fn to_hex(data : Bytes) -> String {
  let digits = "0123456789abcdef"
  let out = StringBuilder()
  for b in data {
    let n = b.to_int()
    out.write_string(digits[n / 16:n / 16 + 1].to_owned())
    out.write_string(digits[n % 16:n % 16 + 1].to_owned())
  }
  out.to_string()
}
