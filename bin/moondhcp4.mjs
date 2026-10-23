#!/usr/bin/env node
// Filesystem host only. All packet, option and config logic is in MoonBit.
import { open, writeFile } from 'node:fs/promises';
const args = process.argv.slice(2);
const usage = 'Usage: node bin/moondhcp4.mjs inspect INPUT.bin [--json]\n       node bin/moondhcp4.mjs normalize INPUT.bin OUTPUT.bin [--json]\n       node bin/moondhcp4.mjs build CONFIG.json OUTPUT.bin [--json]';
function stop(message, code) { console.error(message); process.exit(code); }
if (args.length === 1 && ['--help','-h'].includes(args[0])) { console.log(usage); process.exit(0); }
const [operation, input] = args;
const outputRequired = operation === 'build' || operation === 'normalize';
if (!['inspect','normalize','build'].includes(operation) || !input) stop(usage, 64);
const output = outputRequired ? args[2] : undefined;
const tail = args.slice(outputRequired ? 3 : 2);
if ((outputRequired && (!output || output.startsWith('--'))) || tail.length > 1 || (tail.length && tail[0] !== '--json')) stop(usage, 64);
let engine;
try { engine = await import(new URL('../_build/js/debug/build/bridge/bridge.js', import.meta.url)); }
catch { stop('Build the JS engine first: moon build --target js', 64); }
try {
  // Read a bounded regular file through the same handle, without a stat/read race.
  const handle = await open(input, 'r');
  let data;
  try {
    const info = await handle.stat();
    if (!info.isFile()) stop('Input must be a regular file', 3);
    const limit = operation === 'build' ? 131014 : 65507;
    if (info.size > limit) stop('Input exceeds the profile byte limit', 4);
    const buffer = Buffer.alloc(limit + 1);
    let used = 0;
    while (used < buffer.length) {
      const {bytesRead} = await handle.read(buffer, used, buffer.length - used, null);
      if (!bytesRead) break;
      used += bytesRead;
    }
    if (used > limit) stop('Input exceeds the profile byte limit', 4);
    data = buffer.subarray(0, used);
  } finally { await handle.close(); }
  const payload = operation === 'build' ? new TextDecoder('utf-8',{fatal:true}).decode(data) : data.toString('hex');
  const report = JSON.parse(engine.run(operation, payload));
  if (output && report.code === 0) {
    // Create only; never overwrite a user's input or existing output file.
    await writeFile(output, Buffer.from(report.wireHex,'hex'), {flag:'wx'});
  }
  console.log(tail[0] === '--json' ? JSON.stringify(report) : report.status + ': ' + (report.message ?? `${report.packet?.fragments.length ?? 0} option fragments, ${report.issues?.length ?? 0} diagnostics`));
  process.exitCode = report.code;
} catch (error) { stop('File/host error: ' + error.message, 3); }
