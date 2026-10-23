///|
/// Read a logical four-byte integer after RFC3396 reassembly. Lease durations
/// include the full UInt32 domain (0xffffffff is not converted to -1).
pub fn Packet::u32_option(
  self : Packet,
  code : Int32,
) -> UInt32? raise DhcpError {
  match self.option(code) {
    None => None
    Some(value) => {
      if value.length() != 4 {
        raise InvalidModel("option \{code} is not a four-byte integer")
      }
      Some(read32(value, 0))
    }
  }
}

///|
pub fn Packet::ipv4_list_option(
  self : Packet,
  code : Int32,
) -> Array[Bytes]? raise DhcpError {
  match self.option(code) {
    None => None
    Some(value) => {
      if value.length() == 0 || value.length() % 4 != 0 {
        raise InvalidModel("option \{code} is not a nonempty IPv4 address list")
      }
      let addresses : Array[Bytes] = []
      for offset = 0; offset < value.length(); offset = offset + 4 {
        addresses.push(value[offset:offset + 4].to_owned())
      }
      Some(addresses)
    }
  }
}
