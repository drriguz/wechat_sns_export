// WeChat SNS media keystream generator.
//
// Uses WeChat's official WxIsaac64 WASM module (wasm_video_decode.wasm) to
// generate the ISAAC-64 keystream exactly as the WeChat client does.
//
// Usage: node isaac_keystream.mjs <seed> <byteCount> > keystream.bin
//
// The keystream is emitted in FORWARD order (byte 0 = keystream[0]). Note the
// WASM's own generate() only aligns to 8-byte words when the requested size is
// a multiple of 8, so we always request a rounded-up size and truncate.
import fs from 'fs';
import { createRequire } from 'module';
import path from 'path';
import { fileURLToPath } from 'url';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const seed = process.argv[2];
const size = parseInt(process.argv[3] || '131072', 10);
if (!seed || !(size > 0)) {
  process.stderr.write('usage: node isaac_keystream.mjs <seed> <byteCount>\n');
  process.exit(1);
}

globalThis.self = globalThis;
globalThis.window = globalThis;
globalThis.location = { href: 'file:///isaac/', protocol: 'file:' };
globalThis.VTS_WASM_URL = 'wasm_video_decode.wasm';
globalThis.importScripts = () => {};

let wasmPath = process.env.WX_ISAAC_WASM;
if (!wasmPath) {
  wasmPath = path.join(__dirname, 'wasm_video_decode.wasm');
}

const gluePath = process.env.WX_ISAAC_GLUE;
const gluePathDefault = path.join(__dirname, 'wasm_video_decode.js');
const glueFile = gluePath || gluePathDefault;
if (!fs.existsSync(wasmPath)) {
  process.stderr.write('wasm not found: ' + wasmPath + '\n');
  process.exit(2);
}
if (!fs.existsSync(glueFile)) {
  process.stderr.write('loader not found: ' + glueFile + '\n');
  process.exit(2);
}

const glue = fs.readFileSync(glueFile, 'utf8');
const m = new Function('Module', 'require', glue + '; return Module;')(
  {
    wasmBinary: fs.readFileSync(wasmPath),
    locateFile: (p) => p,
    print: () => {},
    printErr: () => {},
  },
  require,
);
await new Promise((r) => setTimeout(r, 1500));

// Called by the wasm when generate() writes the keystream into wasm memory.
globalThis.wasm_isaac_generate = function (ptr, n) {
  globalThis.__wx_keystream = new Uint8Array(n);
  const view = new Uint8Array(m.HEAPU8.buffer, ptr, n);
  globalThis.__wx_keystream.set(view.reverse());
};

const aligned = Math.ceil(size / 8) * 8;
const isaac = new m.WxIsaac64(seed);
isaac.generate(aligned);
isaac.delete();

let out = globalThis.__wx_keystream;
if (!out || out.length < aligned) {
  process.stderr.write('keystream generation failed\n');
  process.exit(3);
}
process.stdout.write(Buffer.from(out.slice(0, size)));
