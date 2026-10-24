// Writes .br and .gz copies of compressible build output; the server serves them to
// browsers that accept them, so responses need no on-the-fly compression.
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { brotliCompressSync, constants, gzipSync } from 'node:zlib';

const COMPRESSIBLE = /\.(js|mjs|css|html|svg|json|webmanifest|txt|map)$/;
const MIN_SIZE = 1024;

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path);
    else if (COMPRESSIBLE.test(name) && statSync(path).size >= MIN_SIZE) {
      const data = readFileSync(path);
      writeFileSync(`${path}.br`, brotliCompressSync(data, { params: { [constants.BROTLI_PARAM_QUALITY]: 11 } }));
      writeFileSync(`${path}.gz`, gzipSync(data, { level: 9 }));
    }
  }
}

walk(fileURLToPath(new URL('../dist', import.meta.url)));
