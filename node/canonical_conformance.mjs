import fs from 'node:fs';
import { canonical } from './canonical.mjs';

const path = process.argv[2] ?? '../vectors/canonicalization_conformance.json';
const cases = JSON.parse(fs.readFileSync(path, 'utf8'));
let passed = 0;
for (const tc of cases.positive) {
  const got = canonical(tc.value);
  if (got !== tc.canonical_utf8) throw new Error(`${tc.id}: ${got} != ${tc.canonical_utf8}`);
  passed++;
}
for (const tc of cases.negative) {
  let rejected = false;
  try { canonical(tc.value); } catch { rejected = true; }
  if (!rejected) throw new Error(`${tc.id}: unexpectedly accepted`);
  passed++;
}
console.log(`Node canonicalization conformance verified ${passed}/${cases.positive.length + cases.negative.length} cases`);
