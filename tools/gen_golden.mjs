#!/usr/bin/env node
// Generate the golden files in fixtures/ from dosipas-ts.
//
//   node tools/gen_golden.mjs [--dosipas-ts <dir>] [--out <dir>]
//
// For every public dosipas-ts fixture (src/fixtures.ts) and the extra Car Jaune
// tickets (tests/fixtures/car-jaune-tickets.ts) this writes <NAME>.json with:
//   - hex:                    the payload
//   - ticket:                 decodeTicket() output, Uint8Array as lowercase hex, undefined left out
//   - issuingTime, endOfValidityTime, dynamicContentTime: Unix seconds or null
//   - openTicketValidityWindow: {validFrom, validUntil} of the first openTicket, or null
//   - signedBytes:            extractTicket() level1/level2 signedBytes as hex
//   - level2Verification:     verifyLevel2Signature() result
//   - level1Verification:     verifyLevel1Signature() with the key found in tests/fixtures/uic-publickeys.xml
//                             (null when the registry has no key for the issuer/keyId)
//   - level1WithForeignKey:   verifyLevel1Signature() with a P-256 key from the registry that is not the
//                             issuer's, to pin the error paths (DSA unsupported, missing OIDs, ...)
//
// The dosipas-ts package is the one pinned in tools/package.json unless --dosipas-ts
// points at a checkout (its dist/ must be built). The Car Jaune extra tickets and the
// public key XML are only in the git checkout, so they are copied into fixtures/ once and
// read from there afterwards.

import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, unlinkSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const repo = resolve(here, '..');
const args = process.argv.slice(2);
const opt = (name, dflt) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : dflt;
};
const outDir = opt('--out', join(repo, 'fixtures'));
const tsDir = opt('--dosipas-ts', null);

const pkgDir = tsDir ?? join(here, 'node_modules', 'dosipas-ts');
const pkg = JSON.parse(readFileSync(join(pkgDir, 'package.json'), 'utf8'));
const ts = await import(pathToFileURL(join(pkgDir, 'dist', 'index.js')).href);
console.log(`dosipas-ts ${pkg.version} from ${pkgDir}`);

mkdirSync(outDir, { recursive: true });

// Extra inputs that only exist in a git checkout of dosipas-ts.
const carJaunePath = join(outDir, 'car-jaune-tickets.hex');
const keysPath = join(outDir, 'uic-publickeys.xml');
if (tsDir) {
  const src = readFileSync(join(tsDir, 'tests', 'fixtures', 'car-jaune-tickets.ts'), 'utf8');
  const hexes = [...src.matchAll(/'([0-9a-f]+)'/g)].map(m => m[1]);
  // Concatenated string literals: a ticket is a run of literals until a comma + newline + comment or ].
  const tickets = [];
  for (const block of src.split(/\/\/ serial [0-9-]+/).slice(1)) {
    tickets.push([...block.matchAll(/'([0-9a-f]+)'/g)].map(m => m[1]).join(''));
  }
  if (tickets.length === 0 || hexes.length === 0) throw new Error('could not parse car-jaune-tickets.ts');
  writeFileSync(carJaunePath, tickets.join('\n') + '\n');
  const xml = readFileSync(join(tsDir, 'tests', 'fixtures', 'uic-publickeys.xml'), 'utf8');
  writeFileSync(keysPath, xml);
}
if (!existsSync(carJaunePath) || !existsSync(keysPath)) {
  throw new Error('fixtures/car-jaune-tickets.hex or fixtures/uic-publickeys.xml missing: run once with --dosipas-ts <checkout>');
}
const keysXml = readFileSync(keysPath, 'utf8');

const fixtures = [
  ['SAMPLE', ts.SAMPLE_TICKET_HEX],
  ['SNCF_TER', ts.SNCF_TER_TICKET_HEX],
  ['SOLEA', ts.SOLEA_TICKET_HEX],
  ['BUS_ARDECHE', ts.BUS_ARDECHE_TICKET_HEX],
  ['BUS_AIN', ts.BUS_AIN_TICKET_HEX],
  ['DROME_BUS', ts.DROME_BUS_TICKET_HEX],
  ['CTS', ts.CTS_TICKET_HEX],
  ['GRAND_EST_U1_FCB3', ts.GRAND_EST_U1_FCB3_HEX],
  ['CAR_JAUNE', ts.CAR_JAUNE_TICKET_HEX],
];
readFileSync(carJaunePath, 'utf8')
  .split('\n')
  .filter(Boolean)
  .forEach((hex, i) => fixtures.push([`CAR_JAUNE_${i + 1}`, hex]));

const hex = b => Buffer.from(b).toString('hex');
const toJson = v => JSON.parse(JSON.stringify(v, (k, x) => (x instanceof Uint8Array ? hex(x) : x)));
const secs = d => (d instanceof Date && !isNaN(d) ? Math.round(d.getTime() / 1000) : null);

// A registry ECDSA key (an X.509 certificate) that is not the issuer's, used to
// pin the error paths: wrong key, DSA level 1, missing OIDs.
const foreign = ts.parseKeysXml(keysXml).find(k => k.issuerCode === 1187 && k.id === 10 && /ECDSA/.test(k.signatureAlgorithm))
  ?? ts.parseKeysXml(keysXml).find(k => /ECDSA/.test(k.signatureAlgorithm));
if (!foreign) throw new Error('no foreign ECDSA key available');
const foreignKey = { publicKey: foreign.publicKey };

// Remove stale goldens so the embed step never picks up a renamed fixture.
for (const f of readdirSync(outDir)) if (f.endsWith('.json')) unlinkSync(join(outDir, f));

for (const [name, h] of fixtures) {
  const bytes = Buffer.from(h, 'hex');
  const ticket = ts.decodeTicket(h);
  const extracted = ts.extractTicket(bytes);
  const rt = ticket.level2SignedData.level1Data.dataSequence.find(e => e.decoded)?.decoded;
  const open = rt?.transportDocument?.find(d => d.ticket.key === 'openTicket');
  let window = null;
  if (open && rt?.issuingDetail) {
    const w = ts.getOpenTicketValidityWindow(open.ticket.value, rt.issuingDetail);
    if (w) window = { validFrom: secs(w.validFrom), validUntil: secs(w.validUntil) };
  }
  const l2 = await ts.verifyLevel2Signature(bytes);
  const own = ts.findKeyInXml(keysXml, extracted.key);
  const l1 = own ? await ts.verifyLevel1Signature(bytes, own) : null;
  const l1foreign = await ts.verifyLevel1Signature(bytes, foreignKey);
  const golden = {
    name,
    dosipasTsVersion: pkg.version,
    hex: h,
    ticket: toJson(ticket),
    issuingTime: secs(ts.getIssuingTime(ticket)),
    endOfValidityTime: secs(ts.getEndOfValidityTime(ticket)),
    dynamicContentTime: secs(ts.getDynamicContentTime(ticket)),
    openTicketValidityWindow: window,
    signedBytes: {
      level1: hex(extracted.level1.signedBytes),
      level2: hex(extracted.level2.signedBytes),
    },
    level2Verification: { valid: l2.valid, error: l2.error ?? null, algorithm: l2.algorithm ?? null },
    level1Verification: l1
      ? { valid: l1.valid, error: l1.error ?? null, algorithm: l1.algorithm ?? null, publicKey: hex(own.publicKey) }
      : null,
    level1WithForeignKey: {
      valid: l1foreign.valid,
      error: l1foreign.error ?? null,
      algorithm: l1foreign.algorithm ?? null,
      publicKey: hex(foreignKey.publicKey),
    },
  };
  writeFileSync(join(outDir, `${name}.json`), JSON.stringify(golden, null, 1) + '\n');
  console.log(
    `${name.padEnd(18)} ${String(bytes.length).padStart(4)} B  ${ticket.format} ${ticket.level2SignedData.level1Data.dataSequence.map(e => e.dataFormat).join(',')}` +
      `  L2 ${l2.valid}${l2.error ? ' (' + l2.error.slice(0, 50) + ')' : ''}` +
      (l1 ? `  L1 ${l1.valid}${l1.error ? ' (' + l1.error.slice(0, 40) + ')' : ''}` : '  L1 no key'),
  );
}
console.log(`wrote ${fixtures.length} golden files to ${outDir}`);
