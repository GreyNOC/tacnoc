#!/usr/bin/env node
/**
 * Generate a CycloneDX 1.5 SBOM from package-lock.json — self-contained, no
 * extra dependencies. Writes sbom.json at the repo root.
 *
 * Usage: node scripts/generate-sbom.mjs [--dev]
 *   --dev  include devDependencies (default: production only)
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import * as path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const includeDev = process.argv.includes('--dev');

const lock = JSON.parse(readFileSync(path.join(root, 'package-lock.json'), 'utf8'));
const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));

if (lock.lockfileVersion < 2 || !lock.packages) {
  console.error('package-lock.json v2/v3 (with a "packages" map) is required.');
  process.exit(1);
}

function purl(name, version) {
  // Encode scoped names: @scope/name -> %40scope/name
  const encoded = name.startsWith('@') ? '%40' + name.slice(1) : name;
  return `pkg:npm/${encoded}@${version}`;
}

const components = [];
const seen = new Set();

for (const [loc, meta] of Object.entries(lock.packages)) {
  if (loc === '') continue; // the root project
  if (!loc.startsWith('node_modules/')) continue;
  if (meta.dev && !includeDev) continue;
  const name = meta.name ?? loc.split('node_modules/').pop();
  if (!name || !meta.version) continue;
  const key = `${name}@${meta.version}`;
  if (seen.has(key)) continue;
  seen.add(key);

  const component = {
    type: 'library',
    'bom-ref': purl(name, meta.version),
    name,
    version: meta.version,
    purl: purl(name, meta.version),
    scope: meta.dev ? 'optional' : 'required',
  };
  if (meta.license) component.licenses = [{ license: { id: String(meta.license) } }];
  if (meta.resolved) component.externalReferences = [{ type: 'distribution', url: meta.resolved }];
  if (meta.integrity) {
    // npm integrity is <algo>-<base64>; expose as a property for traceability.
    component.properties = [{ name: 'npm:integrity', value: meta.integrity }];
  }
  components.push(component);
}

components.sort((a, b) => a.name.localeCompare(b.name));

const serial = createHash('sha256').update(JSON.stringify(components)).digest('hex').slice(0, 32);

const sbom = {
  bomFormat: 'CycloneDX',
  specVersion: '1.5',
  serialNumber: `urn:uuid:${serial.slice(0, 8)}-${serial.slice(8, 12)}-${serial.slice(12, 16)}-${serial.slice(16, 20)}-${serial.slice(20, 32)}`,
  version: 1,
  metadata: {
    // Note: no wall-clock timestamp — keeps the SBOM reproducible for a given lockfile.
    tools: [{ vendor: 'GreyNOC', name: 'generate-sbom', version: '1.0.0' }],
    component: {
      type: 'application',
      name: pkg.name,
      version: pkg.version,
      ...(pkg.license ? { licenses: [{ license: { id: pkg.license } }] } : {}),
    },
  },
  components,
};

const out = path.join(root, 'sbom.json');
writeFileSync(out, JSON.stringify(sbom, null, 2) + '\n');
console.log(
  `Wrote ${path.relative(root, out)} — ${components.length} components (${includeDev ? 'incl. dev' : 'production only'}).`,
);
