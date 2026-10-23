import {spawnSync} from 'node:child_process';
import {homedir} from 'node:os';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
const cwd=fileURLToPath(new URL('../',import.meta.url));
const moon=process.env.MOON??resolve(homedir(),'.moon/bin',process.platform==='win32'?'moon.exe':'moon');
const python=process.env.PYTHON??(process.platform==='win32'?resolve(cwd,'.venv/Scripts/python.exe'):'python3');
function execute(command,args){
  const result=spawnSync(command,args,{cwd,stdio:'inherit',timeout:60000});
  if(result.error) throw result.error;
  if(result.status!==0) throw new Error(`${command} ${args.join(' ')} failed (${result.status})`);
}
execute(moon,['version','--all']);
execute(python,['tools/fixtures.py','--check']);
execute(python,['tools/fixtures.py']);
execute(python,['tools/scapy_reference.py']);
execute(moon,['fmt']);
const targets=['js','wasm','wasm-gc'];
if(process.env.MOON_NATIVE==='1') targets.push('native');
for(const target of targets) for(const action of ['check','build','test']) execute(moon,[action,'--target',target,'--deny-warn']);
execute(process.execPath,['tools/compare.mjs']);
execute(process.execPath,['tools/scenarios.mjs']);
execute(python,['tools/check_built_with_scapy.py']);
execute(moon,['info']);
execute(moon,['package']);
execute(python,['tools/check_consumer.py']);
console.log('Verified:',targets.join(', '));
