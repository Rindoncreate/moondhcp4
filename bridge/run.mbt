///|
fn obj(entries : Array[(String, Json)]) -> Json {
  Json::object(Map(entries))
}

///|
fn number(n : Int32) -> Json {
  Json::number(n.to_double())
}

///|
fn text(s : String) -> Json {
  Json::string(s)
}

///|
fn ip(data : Bytes) -> String {
  "\{data[0].to_int()}.\{data[1].to_int()}.\{data[2].to_int()}.\{data[3].to_int()}"
}

///|
fn area_name(area : @dhcp.Area) -> String {
  match area {
    Main => "main"
    BootFile => "file"
    ServerName => "sname"
  }
}

///|
fn packet_json(packet : @dhcp.Packet) -> Json {
  let h = packet.header
  let fragments = packet.options.map(o => {
    obj([
      ("code", number(o.code)),
      ("hex", text(@dhcp.to_hex(o.data))),
      ("area", text(area_name(o.area))),
    ])
  })
  let logical : Array[Json] = []
  let seen : Map[Int32, Bool] = Map([])
  for fragment in packet.options {
    if !seen.contains(fragment.code) {
      seen.set(fragment.code, true)
      if packet.option(fragment.code) is Some(value) {
        logical.push(
          obj([
            ("code", number(fragment.code)),
            ("hex", text(@dhcp.to_hex(value))),
          ]),
        )
      }
    }
  }
  obj([
    (
      "header",
      obj([
        ("op", number(h.op)),
        ("htype", number(h.htype)),
        ("hlen", number(h.hlen)),
        ("hops", number(h.hops)),
        ("xid", Json::number(h.xid.to_double())),
        ("secs", number(h.secs)),
        ("flags", number(h.flags)),
        ("ciaddr", text(ip(h.ciaddr))),
        ("yiaddr", text(ip(h.yiaddr))),
        ("siaddr", text(ip(h.siaddr))),
        ("giaddr", text(ip(h.giaddr))),
        ("chaddrHex", text(@dhcp.to_hex(h.chaddr))),
        ("snameHex", text(@dhcp.to_hex(h.sname))),
        ("fileHex", text(@dhcp.to_hex(h.file))),
      ]),
    ),
    ("fragments", Json::array(fragments)),
    ("logicalOptions", Json::array(logical)),
  ])
}

///|
fn field(map : Map[String, Json], key : String) -> String raise @dhcp.DhcpError {
  match map.get(key) {
    Some(String(value)) => value
    _ => raise @dhcp.InvalidModel("build field " + key + " must be a string")
  }
}

///|
fn decimal(raw : String, maximum : Int64) -> Int64 raise @dhcp.DhcpError {
  if raw.length() == 0 ||
    raw.length() > 10 ||
    !raw.iter().all(c => c >= '0' && c <= '9') {
    raise @dhcp.InvalidModel(
      "numeric config values must be unsigned decimal strings",
    )
  }
  let n = @string.parse_int64(raw) catch {
    _ => raise @dhcp.InvalidModel("invalid decimal config value")
  }
  if n > maximum {
    raise @dhcp.InvalidModel("numeric config value exceeds its field range")
  }
  n
}

///|
fn parse_ip(raw : String) -> Bytes raise @dhcp.DhcpError {
  let parts = raw.split(".").to_array()
  if parts.length() != 4 {
    raise @dhcp.InvalidModel("IPv4 config field needs four decimal octets")
  }
  let bytes : Array[Byte] = []
  for part in parts {
    bytes.push(decimal(part.to_owned(), 255L).to_int().to_byte())
  }
  Bytes::from_array(bytes)
}

///|
fn ip_field(
  map : Map[String, Json],
  key : String,
) -> Bytes raise @dhcp.DhcpError {
  match map.get(key) {
    None => b"\x00\x00\x00\x00"
    Some(String(value)) => parse_ip(value)
    _ => raise @dhcp.InvalidModel("IPv4 config fields must be strings")
  }
}

///|
fn build(input : String) -> @dhcp.Packet raise @dhcp.DhcpError {
  if input.length() > 131014 {
    raise @dhcp.Limit("build config exceeds 131014 UTF-16 units")
  }
  let mut nesting = 0
  let mut quoted = false
  let mut escaped = false
  for c in input {
    if quoted {
      if escaped {
        escaped = false
      } else if c == '\\' {
        escaped = true
      } else if c == '"' {
        quoted = false
      }
    } else if c == '"' {
      quoted = true
    } else if c == '{' || c == '[' {
      nesting = nesting + 1
      if nesting > 32 {
        raise @dhcp.Limit("build config nesting exceeds 32")
      }
    } else if c == '}' || c == ']' {
      nesting = nesting - 1
      if nesting < 0 {
        raise @dhcp.InvalidModel("unbalanced build config")
      }
    }
  }
  let json = @json.parse(input) catch {
    _ => raise @dhcp.InvalidModel("invalid JSON build config")
  }
  guard json is Object(map) else {
    raise @dhcp.InvalidModel("build config must be a JSON object")
  }
  for key, _ in map {
    if ![
        "messageType", "xid", "macHex", "ciaddr", "yiaddr", "siaddr", "giaddr", "options",
      ].contains(key) {
      raise @dhcp.InvalidModel("unknown build field: " + key)
    }
  }
  let kind = decimal(field(map, "messageType"), 8L).to_int()
  let xid = decimal(field(map, "xid"), 4294967295L)
    .to_int()
    .reinterpret_as_uint()
  let base = @dhcp.Packet::new(kind, xid, @dhcp.from_hex(field(map, "macHex")))
  let header : @dhcp.Header = {
    ..base.header,
    ciaddr: ip_field(map, "ciaddr"),
    yiaddr: ip_field(map, "yiaddr"),
    siaddr: ip_field(map, "siaddr"),
    giaddr: ip_field(map, "giaddr"),
  }
  let packet : @dhcp.Packet = { header, options: base.options, }
  match map.get("options") {
    None => ()
    Some(Array(options)) => {
      if options.length() > 4095 {
        raise @dhcp.Limit("too many build options")
      }
      for option in options {
        guard option is Object(entry) else {
          raise @dhcp.InvalidModel("each option must be an object")
        }
        for key, _ in entry {
          if !["code", "hex", "area"].contains(key) {
            raise @dhcp.InvalidModel("unknown option config field: " + key)
          }
        }
        let code = decimal(field(entry, "code"), 254L).to_int()
        if code == 0 || code == 53 {
          raise @dhcp.InvalidModel(
            "build options cannot override framing or message type",
          )
        }
        let area = match entry.get("area") {
          None | Some(String("main")) => @dhcp.Main
          Some(String("file")) => @dhcp.BootFile
          Some(String("sname")) => @dhcp.ServerName
          _ =>
            raise @dhcp.InvalidModel("option area must be main, file or sname")
        }
        packet.options.push({
          code,
          data: @dhcp.from_hex(field(entry, "hex")),
          area,
        })
      }
    }
    _ => raise @dhcp.InvalidModel("options must be an array")
  }
  packet
}

///|
/// The host transports files; MoonBit owns all protocol and config decisions.
pub fn run(operation : String, input : String) -> String {
  try {
    let packet = match operation {
      "inspect" | "normalize" => @dhcp.decode(@dhcp.from_hex(input))
      "build" => build(input)
      _ => raise @dhcp.InvalidModel("unknown operation")
    }
    // Also checks caller-controlled build models before emitting a report.
    let encoded = @dhcp.encode(packet)
    let issues = packet.diagnose()
    let bad = issues.any(i => i.severity == "error")
    obj([
      ("profile", text(@dhcp.profile())),
      ("code", number(if bad { 1 } else { 0 })),
      ("status", text(if bad { "diagnostic-error" } else { operation + "-ok" })),
      ("packet", packet_json(packet)),
      (
        "issues",
        Json::array(
          issues.map(i => {
            obj([
              ("severity", text(i.severity)),
              ("code", text(i.code)),
              ("field", text(i.field)),
              ("message", text(i.message)),
            ])
          }),
        ),
      ),
      (
        "wireHex",
        text(
          if !bad && operation != "inspect" {
            @dhcp.to_hex(encoded)
          } else {
            ""
          },
        ),
      ),
    ]).stringify()
  } catch {
    @dhcp.Malformed(offset, message) =>
      error(2, "malformed-wire", message, offset)
    @dhcp.InvalidModel(message) => error(2, "invalid-model", message, -1)
    @dhcp.Limit(message) => error(4, "resource-limit", message, -1)
  }
}

///|
fn error(
  code : Int32,
  status : String,
  message : String,
  offset : Int32,
) -> String {
  obj([
    ("profile", text(@dhcp.profile())),
    ("code", number(code)),
    ("status", text(status)),
    ("message", text(message)),
    ("byteOffset", number(offset)),
  ]).stringify()
}
