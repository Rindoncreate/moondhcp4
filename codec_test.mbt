///|
test "unsigned fixed fields and Ethernet constructor round trip" {
  let packet = @moondhcp4.Packet::new(1, 0xffffffffU, b"\x02\x00\x00\x00\x00\x01")
  let bytes = @moondhcp4.encode(packet)
  assert_eq(bytes.length(), 300)
  let decoded = @moondhcp4.decode(bytes)
  assert_eq(decoded.header.xid, 0xffffffffU)
  assert_eq(decoded.header.hlen, 6)
  assert_eq(decoded.message_type(), Some(1))
  assert_eq(decoded.option(53), Some(b"\x01"))
  assert_true(decoded.diagnose().is_empty())
  assert_eq(@moondhcp4.encode(decoded), bytes)
}

///|
test "RFC3396 joins main then file then sname despite wire layout" {
  let packet = @moondhcp4.Packet::new(2, 7U, b"\x02\x00\x00\x00\x00\x02")
  packet.options.push({ code: 52, data: b"\x03", area: @moondhcp4.Main })
  packet.options.push({ code: 200, data: b"sname", area: @moondhcp4.ServerName })
  packet.options.push({ code: 200, data: b"main", area: @moondhcp4.Main })
  packet.options.push({ code: 200, data: b"file", area: @moondhcp4.BootFile })
  let decoded = @moondhcp4.decode(@moondhcp4.encode(packet))
  assert_eq(decoded.option(200), Some(b"mainfilesname"))
  assert_eq(decoded.options.length(), 5)
  assert_true(decoded.diagnose().is_empty())
}

///|
test "split logical values at arbitrary byte boundaries and retain unknown options" {
  let packet = @moondhcp4.Packet::new(3, 1U, b"\x02\x00\x00\x00\x00\x03")
  let value = Bytes::from_array(Array::make(600, (123 : Byte)))
  for fragment in @moondhcp4.split_option(222, value, @moondhcp4.Main) {
    packet.options.push(fragment)
  }
  let decoded = @moondhcp4.decode(@moondhcp4.encode(packet))
  assert_eq(decoded.option(222), Some(value))
  assert_eq(decoded.options.length(), 4)
}

///|
test "diagnostics check logical fixed lengths after concatenation" {
  let packet = @moondhcp4.Packet::new(5, 1U, b"\x02\x00\x00\x00\x00\x04")
  packet.options.push({ code: 51, data: b"\xff", area: @moondhcp4.Main })
  packet.options.push({ code: 51, data: b"\xff\xff\xff", area: @moondhcp4.Main })
  let decoded = @moondhcp4.decode(@moondhcp4.encode(packet))
  assert_true(decoded.diagnose().is_empty())
  packet.options.push({ code: 51, data: b"\x00", area: @moondhcp4.Main })
  assert_true(packet.diagnose().any(i => i.code == "option-length"))
}

///|
test "malformed inputs are checked errors rather than panics" {
  for bytes in [b"", b"\x01\x02", Bytes::from_array(Array::make(241, (0 : Byte)))] {
    try @moondhcp4.decode(bytes) catch {
      @moondhcp4.Malformed(_, _) => ()
      _ => fail("unexpected error category")
    } noraise { _ => fail("expected structural error") }
  }
}

///|
test "no silent clipping when overloaded fields or headers are invalid" {
  let packet = @moondhcp4.Packet::new(2, 2U, b"\x02\x00\x00\x00\x00\x05")
  packet.options.push({ code: 12, data: b"bad", area: @moondhcp4.BootFile })
  try @moondhcp4.encode(packet) catch {
    @moondhcp4.InvalidModel(_) => ()
    _ => fail("unexpected error category")
  } noraise { _ => fail("expected missing overload error") }
  packet.options.push({ code: 52, data: b"\x01", area: @moondhcp4.Main })
  packet.options.push({ code: 222, data: Bytes::from_array(Array::make(128, (1 : Byte))), area: @moondhcp4.BootFile })
  try @moondhcp4.encode(packet) catch {
    @moondhcp4.Limit(_) => ()
    _ => fail("unexpected error category")
  } noraise { _ => fail("expected field capacity error") }
}

///|
test "empty unknown option and hexadecimal conversion retain bytes" {
  let packet = @moondhcp4.Packet::new(8, 4U, b"\x02\x00\x00\x00\x00\x06")
  packet.options.push({ code: 224, data: b"", area: @moondhcp4.Main })
  let encoded = @moondhcp4.encode(packet)
  assert_eq(@moondhcp4.from_hex(@moondhcp4.to_hex(encoded)), encoded)
  assert_eq(@moondhcp4.decode(encoded).option(224), Some(b""))
  assert_eq(@moondhcp4.decode(encoded).option(225), None)
}

///|
test "typed accessors use logical values and retain unsigned lease times" {
  let packet = @moondhcp4.Packet::new(2, 0U, b"\x02\x00\x00\x00\x00\x01")
  packet.options.push({ code: 51, data: b"\xff", area: @moondhcp4.Main })
  packet.options.push({ code: 51, data: b"\xff\xff\xff", area: @moondhcp4.Main })
  packet.options.push({ code: 6, data: b"\xc0\x00\x02\x01\xc0\x00\x02\x02", area: @moondhcp4.Main })
  assert_eq(packet.u32_option(51), Some(0xffffffffU))
  assert_eq(packet.ipv4_list_option(6), Some([b"\xc0\x00\x02\x01", b"\xc0\x00\x02\x02"]))
  assert_eq(packet.u32_option(59), None)
}

///|
test "wire and fragment resource bounds fail explicitly" {
  try @moondhcp4.decode(Bytes::from_array(Array::make(65508, (0 : Byte)))) catch {
    @moondhcp4.Limit(_) => ()
    _ => fail("unexpected category")
  } noraise { _ => fail("expected byte limit") }
  let packet = @moondhcp4.Packet::new(1, 0U, b"\x02\x00\x00\x00\x00\x01")
  for _ in 0..<4096 {
    packet.options.push({ code: 224, data: b"", area: @moondhcp4.Main })
  }
  try @moondhcp4.encode(packet) catch {
    @moondhcp4.Limit(_) => ()
    _ => fail("unexpected category")
  } noraise { _ => fail("expected fragment limit") }
}
