#!/usr/bin/env node
// Generate random but well-formed fuzz seeds with dosipas-ts 4.1.0 (asn1-per-ts codecs on the
// same JSON schemas as src/dosipas_schema_tables.c).
//
//   node tools/gen_fuzz_corpus.mjs [--count 3000] [--seed 1] [--out fuzz/corpus-gen]
//
// Writes, under --out:
//   decode/  full barcodes (header v1/v2, 0-3 dataSequence entries of FCB1/2/3 with or without an
//            Intercode issuing extension, unknown formats, level 2 data FDC1 / _RICS.ID1 / unknown),
//            signed with real ECDSA P-256/384/521 keys (DER or raw r||s), wrong keys, wrong OIDs
//   schema/  one byte root selector + one UPER value of that root (input format of fuzz_schema)
//   verify/  level 1 key block + barcode (input format of fuzz_verify, see fuzz/fuzz_verify.c)
//   keys/    curve/hash selector + key + signature + data (input format of fuzz_keys)
// Every optional field, extension field, CHOICE alternative and ENUMERATED value is drawn at
// random, integers favour their bounds. Only synthetic data: no real ticket goes in here.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { SchemaBuilder, SchemaCodec } from 'asn1-per-ts';
import { p256, p384, p521 } from '@noble/curves/nist.js';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..');
const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : dflt;
};
const COUNT = Number(opt('--count', 3000));
const OUT = resolve(opt('--out', join(repo, 'fuzz', 'corpus-gen')));

// Deterministic PRNG (mulberry32) so a run can be reproduced.
let state = Number(opt('--seed', 1)) >>> 0;
const rnd = () => {
  state = (state + 0x6d2b79f5) >>> 0;
  let t = state;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
const ri = (lo, hi) => lo + Math.floor(rnd() * (hi - lo + 1));
const pick = a => a[Math.floor(rnd() * a.length)];
const chance = p => rnd() < p;
const bytes = n => Uint8Array.from({ length: n }, () => ri(0, 255));

const schemaDir = join(here, 'node_modules', 'dosipas-ts', 'schemas', 'uic-barcode');
const load = f => {
  const schemas = JSON.parse(readFileSync(join(schemaDir, f), 'utf8'));
  return { schemas, codecs: SchemaBuilder.buildAll(schemas) };
};
const FILES = {
  h1: load('uicBarcodeHeader_v1.schema.json'),
  h2: load('uicBarcodeHeader_v2.schema.json'),
  r1: load('uicRailTicketData_v1.schema.json'),
  r2: load('uicRailTicketData_v2.schema.json'),
  r3: load('uicRailTicketData_v3.schema.json'),
  ic: load('intercode6.schema.json'),
  fdc: load('uicDynamicContentData_v1.schema.json'),
};
const codec = (file, name) => new SchemaCodec(FILES[file].schemas[name], FILES[file].codecs[name]);

const OIDS = ['1.2.840.10045.3.1.7', '1.3.132.0.34', '1.3.132.0.35', '1.2.840.10045.4.3.2', '1.2.840.10045.4.3.3',
  '1.2.840.10045.4.3.4', '1.2.840.113549.1.1.11', '1.2.840.113549.1.1.1', '2.16.840.1.101.3.4.3.2', '1.2.840.10040.4.1',
  '1.2.840.10040.4.3', '2.5.4.3', '0.0', '1.3.6.1.4.1.99999.1', '2.999.18446744073709551615'];
const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 -_./+:';
const UTF = ['é', 'ü', 'Ω', '€', '日本', '🚆', '\u0000', '"', '\\', '\n', '\u001f', '\u007f'];

function randInt(node) {
  const { min, max } = node;
  if (min !== undefined && max !== undefined) {
    const span = max - min;
    const r = rnd();
    if (r < 0.15) return min;
    if (r < 0.3) return max;
    if (r < 0.4 && span > 2) return min + 1;
    if (r < 0.5 && span > 2) return max - 1;
    return min + Math.floor(rnd() * (span + 1));
  }
  const pool = [0, 1, -1, 127, 128, 255, 256, -128, -129, 65535, 65536, 2 ** 31 - 1, -(2 ** 31), 2 ** 32, 2 ** 53 - 1,
    -(2 ** 53 - 1), 1700000000, ri(-1000, 100000)];
  let v = pick(pool);
  if (min !== undefined && v < min) v = min + Math.abs(v % 1000);
  if (max !== undefined && v > max) v = max - Math.abs(v % 1000);
  return v;
}

function sizeOf(node, dflt) {
  if (node.fixedSize !== undefined) return node.fixedSize;
  const lo = node.minSize ?? 0;
  const hi = node.maxSize ?? lo + dflt;
  const r = rnd();
  if (r < 0.15) return lo;
  if (r < 0.25) return Math.min(hi, lo + 200);
  return ri(lo, Math.min(hi, lo + dflt));
}

function randString(node) {
  const n = sizeOf(node, chance(0.1) ? 120 : 12);
  let s = '';
  for (let i = 0; i < n; i++) {
    if (node.type === 'UTF8String' && chance(0.15)) s += pick(UTF);
    else if (node.type === 'IA5String' && chance(0.05)) s += String.fromCharCode(ri(0, 127));
    else s += ALPHA[ri(0, ALPHA.length - 1)];
  }
  return s;
}

// p = probability of including an OPTIONAL/extension field, varied per value tree.
function gen(file, node, p, depth) {
  const reg = FILES[file].schemas;
  switch (node.type) {
    case '$ref': return gen(file, reg[node.ref], p, depth);
    case 'BOOLEAN': return chance(0.5);
    case 'NULL': return null;
    case 'INTEGER': return randInt(node);
    case 'ENUMERATED': {
      const ext = node.extensionValues ?? [];
      return ext.length && chance(0.2) ? pick(ext) : pick(node.values);
    }
    case 'OCTET STRING': return bytes(sizeOf(node, 40));
    case 'BIT STRING': { const n = sizeOf(node, 40); return { data: bytes(Math.ceil(n / 8)), bitLength: n }; }
    case 'OBJECT IDENTIFIER': return pick(OIDS);
    case 'IA5String': case 'VisibleString': case 'UTF8String': return randString(node);
    case 'CHOICE': {
      const ext = node.extensionAlternatives ?? [];
      const alts = depth > 6 ? node.alternatives.slice(0, 1) : node.alternatives;
      const alt = ext.length && chance(0.2) ? pick(ext) : pick(alts);
      return { key: alt.name, value: gen(file, alt.schema, p, depth + 1) };
    }
    case 'SEQUENCE': {
      const out = {};
      const deep = depth > 8 ? 0.05 : p;
      for (const f of node.fields) {
        if ((f.optional || f.defaultValue !== undefined) && !chance(deep)) continue;
        out[f.name] = gen(file, f.schema, p, depth + 1);
      }
      for (const f of node.extensionFields ?? []) {
        if (chance(deep * 0.6)) out[f.name] = gen(file, f.schema, p, depth + 1);
      }
      return out;
    }
    case 'SEQUENCE OF': {
      const n = depth > 6 ? Math.min(node.minSize ?? 0, 1) : sizeOf(node, 3);
      return Array.from({ length: n }, () => gen(file, node.item, p, depth + 1));
    }
    default: throw new Error(`unhandled schema type ${node.type}`);
  }
}

const P = () => pick([0.05, 0.3, 0.5, 0.8, 0.97]);

function tryEncode(file, name, value) {
  try { return codec(file, name).encode(value); } catch { return null; }
}

// Random value of one root, retried until the encoder accepts it (rare constraint misses).
function encodeRandom(file, name, tweak) {
  for (let i = 0; i < 20; i++) {
    const v = gen(file, FILES[file].schemas[name], P(), 0);
    if (tweak) tweak(v);
    const b = tryEncode(file, name, v);
    if (b) return b;
  }
  return bytes(ri(0, 40));
}

function railTicket(version, rics) {
  return encodeRandom(`r${version}`, 'UicRailTicketData', v => {
    if (!v.issuingDetail || !chance(0.7)) return;
    const icBytes = encodeRandom('ic', 'IntercodeIssuingData');
    const id = pick([`_${rics}II1`, '+FRII1', '_3703II1', 'XYZ', `_${rics}II2`, '']);
    v.issuingDetail.extension = { extensionId: id, extensionData: icBytes };
  });
}

function level2Content(rics) {
  const r = rnd();
  if (r < 0.45) return { dataFormat: 'FDC1', data: encodeRandom('fdc', 'UicDynamicContentData') };
  if (r < 0.9) return { dataFormat: pick([`_${rics}.ID1`, '_3703.ID1', '_1.ID1']), data: encodeRandom('ic', 'IntercodeDynamicData') };
  return { dataFormat: pick(['FDC2', 'XYZ', '', '_ab.ID1']), data: bytes(ri(0, 30)) };
}

const CURVES = [
  { name: 'P-256', c: p256, n: 32, key: '1.2.840.10045.3.1.7', sig: '1.2.840.10045.4.3.2' },
  { name: 'P-384', c: p384, n: 48, key: '1.3.132.0.34', sig: '1.2.840.10045.4.3.3' },
  { name: 'P-521', c: p521, n: 66, key: '1.3.132.0.35', sig: '1.2.840.10045.4.3.4' },
];
const HASH = { 'P-256': 'sha256', 'P-384': 'sha384', 'P-521': 'sha512' };

function derInt(b) {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  let v = b.slice(i);
  if (v[0] & 0x80) v = Uint8Array.from([0, ...v]);
  return [0x02, ...derLen(v.length), ...v];
}
function derLen(n) { return n < 128 ? [n] : n < 256 ? [0x81, n] : [0x82, n >> 8, n & 255]; }
function derSig(raw, n) {
  const body = [...derInt(raw.slice(0, n)), ...derInt(raw.slice(n))];
  return Uint8Array.from([0x30, ...derLen(body.length), ...body]);
}

// Sign `data` with hash chosen by `hashCurve` (mismatches are seeds too), DER or raw r||s.
function sign(cv, priv, data, hashCurve = cv) {
  const h = createHash(HASH[hashCurve.name]).update(data).digest();
  const raw = cv.c.sign(h, priv, { prehash: false, lowS: false });
  const sig = raw instanceof Uint8Array ? raw : raw.toCompactRawBytes();
  return chance(0.8) ? derSig(sig, cv.n) : sig;
}

function corrupt(b) {
  const r = rnd();
  if (r < 0.4 || b.length === 0) return b;
  const out = Uint8Array.from(b);
  if (r < 0.7) out[ri(0, out.length - 1)] ^= 1 << ri(0, 7);
  else if (r < 0.85) return out.slice(0, ri(0, out.length));
  else return Uint8Array.from([...out, ...bytes(ri(1, 8))]);
  return out;
}

function spki(cv, pub) {
  // SubjectPublicKeyInfo: SEQ { SEQ { ecPublicKey, curve }, BIT STRING point }
  const oid = s => {
    const parts = s.split('.').map(Number);
    const body = [40 * parts[0] + parts[1]];
    for (const v of parts.slice(2)) {
      const enc = [v & 0x7f];
      for (let x = Math.floor(v / 128); x > 0; x = Math.floor(x / 128)) enc.unshift(0x80 | (x & 0x7f));
      body.push(...enc);
    }
    return [0x06, body.length, ...body];
  };
  const alg = [...oid('1.2.840.10045.2.1'), ...oid(cv.key)];
  const algSeq = [0x30, ...derLen(alg.length), ...alg];
  const bit = [0x03, ...derLen(pub.length + 1), 0, ...pub];
  const body = [...algSeq, ...bit];
  return Uint8Array.from([0x30, ...derLen(body.length), ...body]);
}

function ticket() {
  const v = chance(0.3) ? 1 : 2;
  const hf = `h${v}`;
  const rics = pick([1080, 3703, 9901, 1, 32000, 1187]);
  const l1cv = pick(CURVES);
  const l2cv = pick(CURVES);
  const l1priv = l1cv.c.utils.randomSecretKey();
  const l2priv = l2cv.c.utils.randomSecretKey();
  const l2pub = l2cv.c.getPublicKey(l2priv, chance(0.5));

  // level1Data from the schema, then its interesting parts forced to realistic values.
  const l1 = gen(hf, FILES[hf].schemas.Level1DataType, P(), 0);
  if (chance(0.8)) { l1.securityProviderNum = rics; delete l1.securityProviderIA5; }
  const entries = [];
  for (let i = 0, n = pick([0, 1, 1, 1, 2, 3]); i < n; i++) {
    const r = rnd();
    if (r < 0.85) {
      const fv = pick([1, 2, 3, 3]);
      entries.push({ dataFormat: chance(0.95) ? `FCB${fv}` : `FCB${pick([1, 2, 3].filter(x => x !== fv))}`, data: railTicket(fv, rics) });
    } else {
      entries.push({ dataFormat: pick(['FCB4', 'TLB', '_3703.ID1', 'FDC1', '']), data: bytes(ri(0, 40)) });
    }
  }
  l1.dataSequence = entries;
  const signed = chance(0.85);
  if (signed) {
    if (chance(0.9)) { l1.level1KeyAlg = l1cv.key; l1.level1SigningAlg = l1cv.sig; }
    if (chance(0.9)) { l1.level2KeyAlg = l2cv.key; l1.level2SigningAlg = l2cv.sig; }
    if (chance(0.9)) l1.level2PublicKey = chance(0.9) ? l2pub : corrupt(l2pub);
    if (chance(0.05)) l1.level2SigningAlg = pick(OIDS);
  }
  const header = codec(hf, 'UicBarcodeHeader');
  const l1codec = codec(hf, 'Level1DataType');
  const l2codec = codec(hf, 'Level2DataType');
  let l1raw;
  try { l1raw = l1codec.encodeToRawBytes(l1); } catch { return null; }
  const level1Signature = signed ? corrupt(sign(l1cv, l1priv, l1raw.data, chance(0.9) ? l1cv : pick(CURVES))) : (chance(0.5) ? bytes(ri(0, 8)) : undefined);
  let level2Data;
  if (chance(0.75)) {
    const content = level2Content(rics);
    level2Data = new SchemaCodec(FILES[hf].schemas.Level2DataType.fields.find(f => f.name === 'level2Data').schema)
      .encodeToRawBytes(content);
  }
  const l2signed = l2codec.encodeToRawBytes({ level1Data: l1raw, level1Signature, level2Data });
  const level2Signature = signed && chance(0.9) ? corrupt(sign(l2cv, l2priv, l2signed.data)) : undefined;
  const format = chance(0.97) ? `U${v}` : pick(['U3', 'U', 'X1', '']);
  let payload;
  try { payload = header.encode({ format, level2SignedData: l2signed, level2Signature }); } catch { return null; }
  // Level 1 key in every encoding fuzz_verify accepts.
  const pub = l1cv.c.getPublicKey(l1priv, chance(0.5));
  const keyKind = ri(0, 2);
  const key = keyKind === 0 ? pub : keyKind === 1 ? spki(l1cv, pub) : bytes(ri(0, 100));
  return { payload, key, l1cv };
}

function u16(n) { return [n >> 8, n & 255]; }
const dirs = ['decode', 'schema', 'verify', 'keys'];
for (const d of dirs) mkdirSync(join(OUT, d), { recursive: true });
const write = (d, b) => {
  const name = createHash('sha1').update(b).digest('hex');
  writeFileSync(join(OUT, d, name), b);
};

// fuzz_schema root selector (byte % 8), same order as fuzz/fuzz_schema.c.
const ROOTS = [['h1', 'UicBarcodeHeader'], ['h2', 'UicBarcodeHeader'], ['r1', 'UicRailTicketData'],
  ['r2', 'UicRailTicketData'], ['r3', 'UicRailTicketData'], ['ic', 'IntercodeIssuingData'],
  ['ic', 'IntercodeDynamicData'], ['fdc', 'UicDynamicContentData']];

let made = 0;
for (let i = 0; i < COUNT; i++) {
  const t = ticket();
  if (t) {
    made++;
    write('decode', t.payload);
    // fuzz_verify: [keyAlgSel][sigAlgSel][keyLen:2][key][payload]
    const ksel = CURVES.indexOf(t.l1cv) + 1;
    write('verify', Uint8Array.from([chance(0.8) ? ksel : ri(0, 255), chance(0.8) ? ksel : ri(0, 255), ...u16(t.key.length), ...t.key, ...t.payload]));
  }
  const r = i % ROOTS.length;
  write('schema', Uint8Array.from([r, ...encodeRandom(...ROOTS[r])]));
  if (i % 5 === 0) {
    // fuzz_keys: [curveSel][hashSel][keyLen:2][key][sigLen:2][sig][data]
    const cv = pick(CURVES);
    const priv = cv.c.utils.randomSecretKey();
    const pub = cv.c.getPublicKey(priv, chance(0.5));
    const data = bytes(ri(0, 64));
    const hcv = chance(0.85) ? cv : pick(CURVES);
    const sig = corrupt(sign(cv, priv, data, hcv));
    const key = chance(0.9) ? pub : corrupt(pub);
    write('keys', Uint8Array.from([CURVES.indexOf(cv), CURVES.indexOf(hcv), ...u16(key.length), ...key, ...u16(sig.length), ...sig, ...data]));
  }
}
console.log(`${made} tickets, ${COUNT} schema values written to ${OUT}`);
