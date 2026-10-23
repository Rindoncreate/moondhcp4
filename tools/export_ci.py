"""Export only our public source/build for hosts whose native compiler is blocked.

This is public code, never credentials, environment variables or private files.
The bounded archive is also logged so expired artifact redirect links cannot
prevent source inspection. The receiver uses an exact filename allowlist.
"""
from pathlib import Path
import base64,gzip,json
root=Path(__file__).resolve().parents[1]
names=['model.mbt','codec.mbt','diagnostics.mbt','codec_test.mbt','reference_test.mbt','bridge/run.mbt','moon.mod','moon.pkg','bridge/moon.pkg','pkg.generated.mbti']
files={name:(root/name).read_text(encoding='utf8') for name in names if (root/name).is_file()}
bridge=root/'_build/js/debug/build/bridge/bridge.js'
if bridge.is_file(): files['_build/js/debug/build/bridge/bridge.js']=bridge.read_text(encoding='utf8')
encoded=base64.b64encode(gzip.compress(json.dumps({'files':files}).encode(),mtime=0)).decode()
assert len(encoded)<1000000
print('MOONDHCP4_CI_PAYLOAD_BEGIN')
print(encoded)
print('MOONDHCP4_CI_PAYLOAD_END')
