///|
/// Physical option areas. RFC 3396 aggregation order is Main, BootFile,
/// ServerName, which differs from the byte order of the BOOTP header.
pub(all) enum Area {
  Main
  BootFile
  ServerName
} derive(Eq, Debug)

///|
pub extend Area with Eq::{equal, not_equal}

///|
pub extend Area with @debug.Debug::{to_repr}

///|
pub(all) suberror DhcpError {
  Malformed(Int32, String)
  InvalidModel(String)
  Limit(String)
} derive(Debug)

///|
pub extend DhcpError with @debug.Debug::{to_repr}

///|
/// Fixed-width wire fields; chaddr includes its unused trailing bytes.
/// Inactive sname/file fields are opaque bytes, not assumed to be UTF-8.
pub(all) struct Header {
  op : Int32
  htype : Int32
  hlen : Int32
  hops : Int32
  xid : UInt32
  secs : Int32
  flags : Int32
  ciaddr : Bytes
  yiaddr : Bytes
  siaddr : Bytes
  giaddr : Bytes
  chaddr : Bytes
  sname : Bytes
  file : Bytes
} derive(Eq, Debug)

///|
pub extend Header with Eq::{equal, not_equal}

///|
pub extend Header with @debug.Debug::{to_repr}

///|
/// One physical TLV fragment. Codes 0/255 are framing, not RawOption values.
/// A logical value may span fragments, even across active option areas.
pub(all) struct RawOption {
  code : Int32
  data : Bytes
  area : Area
} derive(Eq, Debug)

///|
pub extend RawOption with Eq::{equal, not_equal}

///|
pub extend RawOption with @debug.Debug::{to_repr}

///|
pub(all) struct Packet {
  header : Header
  options : Array[RawOption]
} derive(Eq, Debug)

///|
pub extend Packet with Eq::{equal, not_equal}

///|
pub extend Packet with @debug.Debug::{to_repr}

///|
pub(all) struct Issue {
  severity : String
  code : String
  field : String
  message : String
} derive(Eq, Debug)

///|
pub extend Issue with Eq::{equal, not_equal}

///|
pub extend Issue with @debug.Debug::{to_repr}

///|
pub fn profile() -> String {
  "dhcpv4-wire-v1"
}

///|
fn zeros(length : Int32) -> Bytes {
  Bytes::from_array(Array::make(length, (0 : Byte)))
}

///|
/// Construct an Ethernet message. This does not assign addresses or send traffic.
pub fn Packet::new(
  message_type : Int32,
  xid : UInt32,
  hardware_address : Bytes,
) -> Packet raise DhcpError {
  if message_type < 1 || message_type > 8 {
    raise InvalidModel("constructor message type must be 1..8")
  }
  if hardware_address.length() != 6 {
    raise InvalidModel(
      "Ethernet constructor requires six hardware address bytes",
    )
  }
  let mac : Array[Byte] = []
  for b in hardware_address {
    mac.push(b)
  }
  while mac.length() < 16 {
    mac.push(0)
  }
  let op = if message_type == 2 || message_type == 5 || message_type == 6 {
    2
  } else {
    1
  }
  let header : Header = {
    op,
    htype: 1,
    hlen: 6,
    hops: 0,
    xid,
    secs: 0,
    flags: 0,
    ciaddr: zeros(4),
    yiaddr: zeros(4),
    siaddr: zeros(4),
    giaddr: zeros(4),
    chaddr: Bytes::from_array(mac),
    sname: zeros(64),
    file: zeros(128),
  }
  {
    header,
    options: [
      {
        code: 53,
        data: Bytes::from_array([message_type.to_byte()]),
        area: Main,
      },
    ],
  }
}

///|
/// Reassemble before interpreting a value. A returned Bytes is immutable.
/// Area order is enforced even if a programmatic model interleaves fragments.
pub fn Packet::option(self : Packet, code : Int32) -> Bytes? {
  let output : Array[Byte] = []
  let mut found = false
  for area in [Main, BootFile, ServerName] {
    for fragment in self.options {
      if fragment.area == area && fragment.code == code {
        found = true
        for b in fragment.data {
          output.push(b)
        }
      }
    }
  }
  if found {
    Some(Bytes::from_array(output))
  } else {
    None
  }
}

///|
pub fn Packet::message_type(self : Packet) -> Int32? {
  match self.option(53) {
    Some(data) if data.length() == 1 => Some(data[0].to_int())
    _ => None
  }
}

///|
/// Explicitly opt into fragmenting a logical option; callers decide whether
/// their peer supports RFC 3396. The codec never guesses peer capabilities.
pub fn split_option(
  code : Int32,
  data : Bytes,
  area : Area,
) -> Array[RawOption] raise DhcpError {
  if code < 1 || code > 254 || code == 52 || code == 53 {
    raise InvalidModel("split_option requires code 1..254 excluding 52 and 53")
  }
  if data.length() > 65507 {
    raise Limit("logical option exceeds the packet profile limit")
  }
  let output : Array[RawOption] = []
  if data.length() == 0 {
    output.push({ code, data, area, })
  }
  let mut offset = 0
  while offset < data.length() {
    let end = if offset + 255 < data.length() {
      offset + 255
    } else {
      data.length()
    }
    output.push({ code, data: data[offset:end].to_owned(), area, })
    offset = end
  }
  output
}
