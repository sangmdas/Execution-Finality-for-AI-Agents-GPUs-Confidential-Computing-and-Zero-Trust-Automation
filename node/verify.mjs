import fs from 'node:fs';
import crypto from 'node:crypto';
import { canonical } from './canonical.mjs';

const path = process.argv[2] ?? '../vectors/interop.json';
const data = JSON.parse(fs.readFileSync(path, 'utf8'));
const key = Buffer.from(data.key_hex, 'hex');
let ok = 0;
for (const vector of data.vectors) {
  const c = canonical(vector.value);
  const sha = crypto.createHash('sha256').update(Buffer.from(c,'utf8')).digest('hex');
  const mac = crypto.createHmac('sha256', key).update(Buffer.from(c,'utf8')).digest('hex');
  if (c !== vector.canonical_utf8) throw new Error(`${vector.id}: canonical mismatch\n${c}\n${vector.canonical_utf8}`);
  if (sha !== vector.sha256) throw new Error(`${vector.id}: sha mismatch`);
  if (mac !== vector.hmac_sha256) throw new Error(`${vector.id}: hmac mismatch`);
  ok++;
}
console.log(`Node interop verified ${ok}/${data.vectors.length} vectors`);
