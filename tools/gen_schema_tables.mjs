#!/usr/bin/env node
// Generate the compact UPER schema tables used by the dosipas-c decoder from the
// dosipas-ts JSON schemas.
//
//   node tools/gen_schema_tables.mjs [--schemas <dir>] [--out-c <file>] [--out-h <file>]
//
// Default schema dir: tools/node_modules/dosipas-ts/schemas/uic-barcode (pinned in
// tools/package.json). The output is deterministic for a given schema set.
//
// Every schema node (SEQUENCE, CHOICE, INTEGER, ...) becomes one 16-byte row of
// `ds_nodes[]`. Identical sub-schemas are shared: the dosipas-ts schemas inline
// every referenced type, so the same ENUMERATED or SEQUENCE appears hundreds of
// times, and the three FCB versions share most of their types. Sharing is
// computed by iterative structural hashing (bisimulation), which handles the
// recursive `$ref` types (ViaStationType) correctly.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..');

const args = process.argv.slice(2);
function opt(name, dflt) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : dflt;
}
const schemaDir = opt('--schemas', join(here, 'node_modules', 'dosipas-ts', 'schemas', 'uic-barcode'));
const outC = opt('--out-c', join(repo, 'src', 'dosipas_schema_tables.c'));
const outH = opt('--out-h', join(repo, 'src', 'dosipas_schema_names.h'));

let tsVersion = 'unknown';
try {
  tsVersion = JSON.parse(readFileSync(join(schemaDir, '..', '..', 'package.json'), 'utf8')).version;
} catch {
  /* schemas given without a package.json */
}

// Roots we need, in a fixed order: (C macro name, file, type name).
const ROOTS = [
  ['DS_ROOT_HEADER_V1', 'uicBarcodeHeader_v1.schema.json', 'UicBarcodeHeader'],
  ['DS_ROOT_HEADER_V2', 'uicBarcodeHeader_v2.schema.json', 'UicBarcodeHeader'],
  ['DS_ROOT_RAIL_TICKET_V1', 'uicRailTicketData_v1.schema.json', 'UicRailTicketData'],
  ['DS_ROOT_RAIL_TICKET_V2', 'uicRailTicketData_v2.schema.json', 'UicRailTicketData'],
  ['DS_ROOT_RAIL_TICKET_V3', 'uicRailTicketData_v3.schema.json', 'UicRailTicketData'],
  ['DS_ROOT_INTERCODE_ISSUING', 'intercode6.schema.json', 'IntercodeIssuingData'],
  ['DS_ROOT_INTERCODE_DYNAMIC', 'intercode6.schema.json', 'IntercodeDynamicData'],
  ['DS_ROOT_DYNAMIC_CONTENT_V1', 'uicDynamicContentData_v1.schema.json', 'UicDynamicContentData'],
];

// Must match src/dosipas_schema.h.
const KIND = {
  BOOLEAN: 1,
  INTEGER: 2,
  ENUMERATED: 3,
  'OCTET STRING': 4,
  'OBJECT IDENTIFIER': 5,
  IA5String: 6,
  UTF8String: 7,
  CHOICE: 8,
  SEQUENCE: 9,
  'SEQUENCE OF': 10,
};
const F_EXTENSIBLE = 0x01;
const F_RANGE = 0x02; // INTEGER with both bounds
const F_SIZE_FIXED = 0x04;
const F_SIZE_RANGE = 0x08;
const F_LEN_UNCONSTRAINED = 0x10; // size range wider than 65536: length is an unconstrained determinant
const FF_OPTIONAL = 0x01;
const FF_DEFAULT = 0x02;

function bitsFor(range) {
  if (range <= 0) throw new Error(`invalid range ${range}`);
  if (range === 1) return 0;
  return Math.ceil(Math.log2(range));
}

// ---------------------------------------------------------------------------
// 1. Load schemas into an in-memory graph
// ---------------------------------------------------------------------------

/** @type {Map<string, Map<string, Node>>} file -> type name -> node */
const registry = new Map();
/** @type {Node[]} */
const allNodes = [];

class Node {
  constructor(file, json) {
    this.file = file;
    this.json = json;
    this.kind = json.type;
    /** @type {Node[]} child nodes in schema order (fields, ext fields, alternatives, item) */
    this.children = [];
    this.id = allNodes.length;
    this.cls = -1;
    allNodes.push(this);
  }
}

function build(file, json) {
  if (json.type === '$ref') {
    return { ref: json.ref, file };
  }
  const n = new Node(file, json);
  switch (json.type) {
    case 'SEQUENCE':
      for (const f of json.fields) n.children.push(build(file, f.schema));
      for (const f of json.extensionFields ?? []) n.children.push(build(file, f.schema));
      break;
    case 'CHOICE':
      for (const a of json.alternatives) n.children.push(build(file, a.schema));
      for (const a of json.extensionAlternatives ?? []) n.children.push(build(file, a.schema));
      break;
    case 'SEQUENCE OF':
      n.children.push(build(file, json.item));
      break;
    case 'BOOLEAN':
    case 'INTEGER':
    case 'ENUMERATED':
    case 'OCTET STRING':
    case 'OBJECT IDENTIFIER':
    case 'IA5String':
    case 'UTF8String':
      if (json.alphabet) throw new Error('permitted-alphabet constraints are not supported');
      break;
    default:
      throw new Error(`unsupported schema type ${json.type} in ${file}`);
  }
  return n;
}

const files = [...new Set(ROOTS.map(r => r[1]))];
for (const file of files) {
  const json = JSON.parse(readFileSync(join(schemaDir, file), 'utf8'));
  const types = new Map();
  for (const [name, schema] of Object.entries(json)) {
    const n = build(file, schema);
    if (!(n instanceof Node)) throw new Error(`top-level $ref ${name} in ${file}`);
    types.set(name, n);
  }
  registry.set(file, types);
}
// Resolve $ref placeholders to the top-level node of the same file.
for (const n of allNodes) {
  n.children = n.children.map(c => {
    if (c instanceof Node) return c;
    const target = registry.get(c.file)?.get(c.ref);
    if (!target) throw new Error(`unresolved $ref ${c.ref} in ${c.file}`);
    return target;
  });
}

// ---------------------------------------------------------------------------
// 2. Structural sharing by iterative hashing
// ---------------------------------------------------------------------------

function sig0(n) {
  const j = n.json;
  switch (j.type) {
    case 'SEQUENCE':
      return JSON.stringify([
        'S',
        j.fields.map(f => [f.name, !!f.optional, 'defaultValue' in f ? f.defaultValue : null]),
        j.extensionFields ? j.extensionFields.map(f => [f.name, !!f.optional, 'defaultValue' in f ? f.defaultValue : null]) : null,
      ]);
    case 'CHOICE':
      return JSON.stringify(['C', j.alternatives.map(a => a.name), j.extensionAlternatives ? j.extensionAlternatives.map(a => a.name) : null]);
    case 'SEQUENCE OF':
      return JSON.stringify(['L', j.fixedSize ?? null, j.minSize ?? null, j.maxSize ?? null, !!j.extensible]);
    case 'ENUMERATED':
      return JSON.stringify(['E', j.values, j.extensionValues ?? null]);
    case 'INTEGER':
      return JSON.stringify(['I', j.min ?? null, j.max ?? null, !!j.extensible]);
    case 'OCTET STRING':
    case 'IA5String':
    case 'UTF8String':
      return JSON.stringify([j.type, j.fixedSize ?? null, j.minSize ?? null, j.maxSize ?? null, !!j.extensible]);
    default:
      return JSON.stringify([j.type]);
  }
}

const base = allNodes.map(sig0);
let cls = allNodes.map(() => 0);
let classCount = 1;
for (let iter = 0; ; iter++) {
  const map = new Map();
  const next = new Array(allNodes.length);
  for (const n of allNodes) {
    const key = base[n.id] + '|' + n.children.map(c => cls[c.id]).join(',');
    let id = map.get(key);
    if (id === undefined) {
      id = map.size;
      map.set(key, id);
    }
    next[n.id] = id;
  }
  cls = next;
  if (map.size === classCount) break; // stable partition
  classCount = map.size;
  if (iter > 200) throw new Error('hashing did not converge');
}
// One representative node per class, in order of first appearance.
const reps = [];
const seen = new Map();
for (const n of allNodes) {
  if (!seen.has(cls[n.id])) {
    seen.set(cls[n.id], reps.length);
    reps.push(n);
  }
  n.cls = seen.get(cls[n.id]);
}
const nodeIndex = n => n.cls;

// ---------------------------------------------------------------------------
// 3. Emit tables
// ---------------------------------------------------------------------------

const strings = new Map(); // string -> offset
let pool = '';
function str(s) {
  if (strings.has(s)) return strings.get(s);
  const off = pool.length;
  strings.set(s, off);
  pool += s + '\0';
  return off;
}
str(''); // offset 0 is the empty string

const fields = []; // {name, node, flags, dflt}
const alts = []; // {name, node}
const enumNames = []; // string offsets
const defaults = []; // int32 values
const defaultIndex = new Map();
function defaultSlot(v) {
  if (!defaultIndex.has(v)) {
    defaultIndex.set(v, defaults.length);
    defaults.push(v);
  }
  return defaultIndex.get(v);
}

const rows = [];
for (const n of reps) {
  const j = n.json;
  const row = { kind: KIND[j.type], flags: 0, bits: 0, preamble: 0, count: 0, ext_count: 0, aux: 0, aux2: 0, min: 0, comment: j.type };
  const sizeConstraint = () => {
    if (j.fixedSize !== undefined) {
      row.flags |= F_SIZE_FIXED;
      row.min = j.fixedSize;
    } else if (j.minSize !== undefined && j.maxSize !== undefined) {
      row.flags |= F_SIZE_RANGE;
      row.min = j.minSize;
      const range = j.maxSize - j.minSize + 1;
      if (range > 65536) row.flags |= F_LEN_UNCONSTRAINED;
      else row.bits = bitsFor(range);
    } else if (j.minSize !== undefined || j.maxSize !== undefined) {
      throw new Error('half-open size constraint not supported');
    }
    if (j.extensible) row.flags |= F_EXTENSIBLE;
  };
  switch (j.type) {
    case 'SEQUENCE': {
      const all = [...j.fields.map(f => [f, false]), ...(j.extensionFields ?? []).map(f => [f, true])];
      row.count = j.fields.length;
      row.ext_count = (j.extensionFields ?? []).length;
      if (j.extensionFields) row.flags |= F_EXTENSIBLE;
      row.aux = fields.length;
      let pre = 0;
      all.forEach(([f, isExt], k) => {
        const child = n.children[k];
        let flags = 0;
        let dflt = 0xffff;
        if (f.optional) flags |= FF_OPTIONAL;
        if ('defaultValue' in f) {
          flags |= FF_DEFAULT;
          const cj = child.json;
          if (cj.type === 'INTEGER') {
            if (!Number.isInteger(f.defaultValue) || f.defaultValue > 0x7fffffff || f.defaultValue < -0x80000000) throw new Error(`default ${f.defaultValue} not int32`);
            dflt = defaultSlot(f.defaultValue);
          } else if (cj.type === 'ENUMERATED') {
            const idx = cj.values.indexOf(f.defaultValue);
            if (idx < 0) throw new Error(`enum default ${f.defaultValue} not a root value of ${f.name}`);
            dflt = defaultSlot(idx);
          } else if (cj.type === 'BOOLEAN') {
            dflt = defaultSlot(f.defaultValue ? 1 : 0);
          } else if (cj.type === 'IA5String' || cj.type === 'UTF8String') {
            dflt = defaultSlot(str(f.defaultValue));
          } else {
            throw new Error(`unsupported default type ${cj.type} for ${f.name}`);
          }
        }
        if (!isExt && (f.optional || 'defaultValue' in f)) pre++;
        fields.push({ name: str(f.name), node: nodeIndex(child), flags, dflt, fname: f.name });
      });
      if (pre > 255) throw new Error('too many optional fields');
      row.preamble = pre;
      row.comment = `SEQUENCE ${j.fields.map(f => f.name).slice(0, 3).join(',')}${j.fields.length > 3 ? ',...' : ''}`;
      break;
    }
    case 'CHOICE': {
      const all = [...j.alternatives, ...(j.extensionAlternatives ?? [])];
      row.count = j.alternatives.length;
      row.ext_count = (j.extensionAlternatives ?? []).length;
      if (j.extensionAlternatives) row.flags |= F_EXTENSIBLE;
      row.bits = bitsFor(j.alternatives.length);
      row.aux = alts.length;
      all.forEach((a, k) => alts.push({ name: str(a.name), node: nodeIndex(n.children[k]), aname: a.name }));
      row.comment = `CHOICE ${j.alternatives.map(a => a.name).slice(0, 3).join(',')}${all.length > 3 ? ',...' : ''}`;
      break;
    }
    case 'SEQUENCE OF':
      row.aux = nodeIndex(n.children[0]);
      sizeConstraint();
      break;
    case 'ENUMERATED':
      row.count = j.values.length;
      row.ext_count = (j.extensionValues ?? []).length;
      if (j.extensionValues) row.flags |= F_EXTENSIBLE;
      row.bits = bitsFor(j.values.length);
      row.aux = enumNames.length;
      for (const v of [...j.values, ...(j.extensionValues ?? [])]) enumNames.push(str(v));
      row.comment = `ENUMERATED ${j.values.slice(0, 3).join(',')}${j.values.length > 3 ? ',...' : ''}`;
      break;
    case 'INTEGER':
      if (j.extensible) throw new Error('extensible INTEGER not supported');
      if (j.min !== undefined && j.max !== undefined) {
        row.flags |= F_RANGE;
        row.min = j.min;
        const range = j.max - j.min + 1;
        const b = bitsFor(range);
        if (b > 32) throw new Error(`INTEGER range needs ${b} bits`);
        row.bits = b;
        if (j.min < -0x80000000 || j.min > 0x7fffffff) throw new Error('INTEGER min not int32');
        row.comment = `INTEGER (${j.min}..${j.max})`;
      } else if (j.min !== undefined || j.max !== undefined) {
        throw new Error('semi-constrained INTEGER not supported');
      }
      break;
    case 'OCTET STRING':
    case 'IA5String':
    case 'UTF8String':
      sizeConstraint();
      break;
    case 'BOOLEAN':
    case 'OBJECT IDENTIFIER':
      break;
    default:
      throw new Error('unreachable');
  }
  rows.push(row);
}

if (rows.length > 0xfffe || fields.length > 0xfffe || alts.length > 0xfffe || enumNames.length > 0xfffe) {
  throw new Error('table too large for 16-bit indices');
}
if (pool.length > 0xffff) throw new Error(`string pool too large (${pool.length})`);

const roots = ROOTS.map(([macro, file, type]) => {
  const n = registry.get(file).get(type);
  return [macro, nodeIndex(n), `${file}:${type}`];
});

// Names used by the typed binding layer: every field and alternative name gets a macro.
const names = [...new Set([...fields.map(f => f.fname), ...alts.map(a => a.aname)])].sort();
const cIdent = s => s.replace(/[^A-Za-z0-9_]/g, '_');

function cString(s) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0) out += '\\0';
    else if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += '\\\\';
    else if (c < 0x20 || c > 0x7e) out += `\\x${c.toString(16).padStart(2, '0')}`;
    else out += s[i];
    if (c === 0) out += '"\n  "'; // one pool entry per source line
  }
  return out;
}

const banner = `/* Generated by tools/gen_schema_tables.mjs from the dosipas-ts ${tsVersion} JSON schemas. DO NOT EDIT. */`;

const h = [];
h.push(banner);
h.push('#ifndef DOSIPAS_SCHEMA_NAMES_H');
h.push('#define DOSIPAS_SCHEMA_NAMES_H');
h.push('');
h.push(`#define DS_SCHEMA_SOURCE_VERSION "dosipas-ts ${tsVersion}"`);
h.push(`#define DS_NODE_COUNT ${rows.length}`);
h.push(`#define DS_FIELD_COUNT ${fields.length}`);
h.push(`#define DS_ALT_COUNT ${alts.length}`);
h.push(`#define DS_ENUM_NAME_COUNT ${enumNames.length}`);
h.push(`#define DS_DEFAULT_COUNT ${defaults.length}`);
h.push(`#define DS_STRING_POOL_SIZE ${pool.length}`);
h.push('');
h.push('/* Root schema nodes (indices into ds_nodes). */');
for (const [macro, idx, what] of roots) h.push(`#define ${macro} ${idx} /* ${what} */`);
h.push('');
h.push('/* Field and alternative names as string-pool offsets. Compare with ds_field_t.name / ds_alt_t.name. */');
for (const nm of names) h.push(`#define DS_NAME_${cIdent(nm)} ${str(nm)}`);
h.push('');
h.push('#endif /* DOSIPAS_SCHEMA_NAMES_H */');
h.push('');

const c = [];
c.push(banner);
c.push('#include "dosipas_schema.h"');
c.push('#include "dosipas_schema_names.h"');
c.push('');
c.push('/* The string pool is one literal longer than the 4095 bytes C99 guarantees; every compiler we target accepts it. */');
c.push('#if defined(__GNUC__)');
c.push('#pragma GCC diagnostic ignored "-Woverlength-strings"');
c.push('#endif');
c.push('');
c.push(`const char ds_strings[DS_STRING_POOL_SIZE] =\n  "${cString(pool.slice(0, -1))}";`);
c.push('');
c.push('const ds_node_t ds_nodes[DS_NODE_COUNT] = {');
rows.forEach((r, i) => {
  c.push(`  /* ${i} */ {${r.kind}, 0x${r.flags.toString(16).padStart(2, '0')}, ${r.bits}, ${r.preamble}, ${r.count}, ${r.ext_count}, ${r.aux}, ${r.aux2}, ${r.min}}, /* ${r.comment} */`);
});
c.push('};');
c.push('');
c.push('const ds_field_t ds_fields[DS_FIELD_COUNT] = {');
fields.forEach((f, i) => {
  c.push(`  /* ${i} */ {${f.name}, ${f.node}, ${f.flags}, ${f.dflt}}, /* ${f.fname} */`);
});
c.push('};');
c.push('');
c.push(`const ds_alt_t ds_alts[${alts.length || 1}] = {`);
alts.forEach((a, i) => c.push(`  /* ${i} */ {${a.name}, ${a.node}}, /* ${a.aname} */`));
c.push('};');
c.push('');
c.push(`const uint16_t ds_enum_names[${enumNames.length || 1}] = {`);
for (let i = 0; i < enumNames.length; i += 16) c.push('  ' + enumNames.slice(i, i + 16).join(', ') + ',');
c.push('};');
c.push('');
c.push(`const int32_t ds_defaults[${defaults.length || 1}] = {`);
for (let i = 0; i < defaults.length; i += 16) c.push('  ' + defaults.slice(i, i + 16).join(', ') + ',');
c.push('};');
c.push('');

mkdirSync(dirname(outC), { recursive: true });
mkdirSync(dirname(outH), { recursive: true });
writeFileSync(outC, c.join('\n'));
writeFileSync(outH, h.join('\n'));

const bytes = rows.length * 16 + fields.length * 8 + alts.length * 4 + enumNames.length * 2 + defaults.length * 4 + pool.length;
console.log(`schemas: ${files.length} files, ${allNodes.length} schema nodes -> ${rows.length} shared nodes`);
console.log(`fields ${fields.length}, alternatives ${alts.length}, enum names ${enumNames.length}, defaults ${defaults.length}, string pool ${pool.length} B`);
console.log(`table footprint: ${bytes} bytes (${(bytes / 1024).toFixed(1)} KiB) -> ${outC}`);
