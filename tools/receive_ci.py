"""Receive generated public sources from a verified run; no paths are executed."""
from pathlib import Path
import base64,gzip,json,sys
root=Path(__file__).resolve().parents[1]
names={'model.mbt','codec.mbt','values.mbt','diagnostics.mbt','codec_test.mbt','reference_test.mbt','bridge/run.mbt','moon.mod','moon.pkg','bridge/moon.pkg','pkg.generated.mbti','_build/js/debug/build/bridge/bridge.js'}
encoded=sys.stdin.read().strip()
assert len(encoded)<1000000
raw=gzip.decompress(base64.b64decode(encoded,validate=True))
assert len(raw)<5000000
files=json.loads(raw)['files']
for name,content in files.items():
    assert name in names
    path=(root/name).resolve()
    assert path.is_relative_to(root.resolve())
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(content,encoding='utf8',newline='\n')
print('Received verified public source/build files:',len(files))
