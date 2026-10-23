import {readFile,writeFile,mkdir} from 'node:fs/promises';
import assert from 'node:assert/strict';
import {run} from '../_build/js/debug/build/bridge/bridge.js';
const fixtures=JSON.parse(await readFile(new URL('../fixtures/wire.json',import.meta.url),'utf8')).cases;
const results=[];
for(const c of fixtures){
  const actual=JSON.parse(run('inspect',c.hex));
  assert.equal(actual.code,c.expectedCode,c.name);
  for(const [code,hex] of Object.entries(c.logical)){
    assert.equal(actual.packet.logicalOptions.find(o=>o.code===Number(code))?.hex,hex,c.name+': logical '+code);
  }
  if(actual.code===0){
    const normalized=JSON.parse(run('normalize',c.hex));
    assert.equal(normalized.code,0,c.name);
    const twice=JSON.parse(run('normalize',normalized.wireHex));
    assert.equal(twice.wireHex,normalized.wireHex,c.name+': normalization idempotence');
    assert.deepEqual(twice.packet.logicalOptions,normalized.packet.logicalOptions,c.name+': logical values retained');
  }
  results.push({name:c.name,expectedCode:c.expectedCode,actualCode:actual.code});
}
const independentlyGenerated=JSON.parse(await readFile(new URL('../_build/scapy-generated.json',import.meta.url),'utf8'));
for(const c of independentlyGenerated) assert.equal(JSON.parse(run('inspect',c.hex)).code,0,c.name);
for(const name of ['discover','offer']){
  const spec=await readFile(new URL('../examples/'+name+'.json',import.meta.url),'utf8');
  const report=JSON.parse(run('build',spec));
  assert.equal(report.code,0,name);
  await writeFile(new URL('../_build/'+name+'-built.bin',import.meta.url),Buffer.from(report.wireHex,'hex'));
}
const oversized='['.repeat(40)+']'.repeat(40);
assert.equal(JSON.parse(run('build',oversized)).code,4,'config depth bound');
for(const spec of ['{}','{"messageType":"1","xid":"4294967296","macHex":"020000000001"}','{"messageType":1,"xid":"1","macHex":"020000000001"}']) assert.equal(JSON.parse(run('build',spec)).code,2,'invalid builder config');
let seed=0x12345678;
const random=()=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;};
const valid=Buffer.from(fixtures[0].hex,'hex');
let mutationCases=0;
for(let i=0;i<1500;i++){
  const data=i<300?valid.subarray(0,i):Buffer.from(valid);
  if(i>=300) for(let n=0;n<1+random()%8;n++) data[random()%data.length]=random()&255;
  const result=JSON.parse(run('inspect',data.toString('hex')));
  assert.ok([0,1,2,4].includes(result.code),'bounded result instead of panic');
  mutationCases++;
}
const report={handwrittenWireAssertions:results.length,independentlyGeneratedScapyMessages:independentlyGenerated.length,mutationCasesWithoutUncaughtFailure:mutationCases,normalizationChecked:true,results};
await writeFile(new URL('../_build/differential-report.json',import.meta.url),JSON.stringify(report,null,2)+'\n');
console.log(JSON.stringify({handwrittenWireAssertions:results.length,independentlyGeneratedScapyMessages:independentlyGenerated.length,mutationCasesWithoutUncaughtFailure:mutationCases}));
