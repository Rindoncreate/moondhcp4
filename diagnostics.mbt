///|
/// This is a documented wire-profile check, not a stateful DHCP server/client
/// verifier. Structural decode success alone is not a protocol acceptance.
pub fn Packet::diagnose(self : Packet) -> Array[Issue] {
  let issues : Array[Issue] = []
  fn error(code : String, field : String, message : String) -> Unit {
    issues.push({ severity: "error", code, field, message })
  }
  match self.message_type() {
    Some(kind) if kind >= 1 && kind <= 8 => {
      let reply = kind == 2 || kind == 5 || kind == 6
      if (reply && self.header.op != 2) || (!reply && self.header.op != 1) {
        error("message-op", "op", "BOOTP op conflicts with DHCP message type")
      }
    }
    _ => error("message-type", "option/53", "requires a one-byte DHCP message type 1..8")
  }
  for (code, length) in [(1, 4), (50, 4), (51, 4), (54, 4), (57, 2), (58, 4), (59, 4)] {
    if self.option(code) is Some(value) {
      if value.length() != length {
        error("option-length", "option/\{code}", "invalid reassembled fixed-width option length")
      }
    }
  }
  for code in [3, 6] {
    if self.option(code) is Some(value) {
      if value.length() == 0 || value.length() % 4 != 0 {
        error("address-list", "option/\{code}", "address list needs a positive multiple of four bytes")
      }
    }
  }
  for code in [12, 15, 55, 60] {
    if self.option(code) is Some(value) {
      if value.length() == 0 {
        error("empty-option", "option/\{code}", "this option must not be empty")
      }
    }
  }
  if self.option(61) is Some(value) {
    if value.length() < 2 {
      error("client-id", "option/61", "client identifier needs at least two bytes")
    }
  }
  if self.option(57) is Some(value) {
    if value.length() == 2 && read16(value, 0) < 576 {
      error("message-size", "option/57", "maximum DHCP message size must be at least 576")
    }
  }
  if (self.header.flags & 32767) != 0 {
    issues.push({ severity: "warning", code: "reserved-flags", field: "flags", message: "reserved flag bits are set and retained" })
  }
  issues
}
