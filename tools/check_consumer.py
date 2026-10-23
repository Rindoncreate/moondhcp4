"""Compile a separate consumer against the packaged source in a fresh workspace.
This deliberately does not claim an install from the unpublished registry.
"""
from pathlib import Path
import os,shutil,subprocess,tempfile,zipfile
root=Path(__file__).resolve().parents[1]
archive=root/'_build/publish/Rindoncreate-moondhcp4-0.1.0.zip'
moon=os.environ.get('MOON') or shutil.which('moon')
assert moon,'MoonBit CLI must be available'
with tempfile.TemporaryDirectory(prefix='moondhcp4-consumer-') as folder:
    workspace=Path(folder)
    library=workspace/'library'
    library.mkdir()
    with zipfile.ZipFile(archive) as package:
        for member in package.infolist():
            target=(library/member.filename).resolve()
            assert target.is_relative_to(library.resolve())
            assert not any(part in {'.git','.venv','node_modules','_build','__pycache__'} for part in Path(member.filename).parts)
        package.extractall(library)
    assert (library/'moon.mod').exists(),'package must contain its root module manifest'
    consumer=workspace/'consumer'
    consumer.mkdir()
    (workspace/'moon.work').write_text('members = [ "library", "consumer" ]\n',encoding='utf8')
    (consumer/'moon.mod').write_text('name = "probe/dhcpconsumer"\nversion = "0.1.0"\nimport { "Rindoncreate/moondhcp4@0.1.0", }\n',encoding='utf8')
    (consumer/'moon.pkg').write_text('import { "Rindoncreate/moondhcp4" @dhcp, }\n',encoding='utf8')
    (consumer/'consumer.mbt').write_text('''///|
pub fn lease_after_roundtrip() -> UInt? raise @dhcp.DhcpError {
  let reply = @dhcp.Packet::new(2, 0xffffffffU, b"\\x02\\x00\\x00\\x00\\x00\\x01")
  reply.options.push({ code: 51, data: b"\\xff\\xff\\xff\\xff", area: @dhcp.Main })
  let decoded = @dhcp.decode(@dhcp.encode(reply))
  if decoded.header.xid != 0xffffffffU || !decoded.diagnose().is_empty() {
    raise @dhcp.InvalidModel("consumer roundtrip failed")
  }
  decoded.u32_option(51)
}
''',encoding='utf8')
    (consumer/'consumer_test.mbt').write_text('''///|
test "external packaged consumer" {
  assert_eq(@dhcpconsumer.lease_after_roundtrip(), Some(0xffffffffU))
}
''',encoding='utf8')
    for target in ['js','native']:
        subprocess.run([moon,'check','--target',target,'--deny-warn'],cwd=consumer,check=True,timeout=60)
        subprocess.run([moon,'test','--target',target,'--deny-warn'],cwd=consumer,check=True,timeout=60)
print('Separate source-package consumer passed on JS and native; no registry publication is implied')
