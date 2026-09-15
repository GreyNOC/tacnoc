/**
 * A minimal ZIP writer and reader — PKZIP APPNOTE 6.3, methods 0 (store) and
 * 8 (deflate), UTF-8 names, no ZIP64, no encryption.
 *
 * Evidence bundles are ZIP because that is what a recipient can open anywhere
 * without tooling. Nothing in the runtime dependency tree writes archives (see
 * `sbom.json`), and taking a dependency for two dozen lines of header layout is
 * a worse trade than owning them: this is a container format, not a primitive —
 * the compression itself is `node:zlib`.
 *
 * The reader is not a convenience. A written bundle is read back and every CRC
 * checked before the app reports success, and the tests verify structure with
 * something other than the writer's own assumptions.
 */

import * as zlib from 'node:zlib';

export interface ZipEntry {
  /** Forward-slash path inside the archive. Absolute, `..`, `.` and backslash paths are refused. */
  path: string;
  data: Buffer | string;
  mtime?: Date;
}

export interface ZipOptions {
  /** Timestamp for entries that do not carry their own. Defaults to now. */
  mtime?: Date;
}

export interface ZipListedEntry {
  path: string;
  data: Buffer;
  /** 0 = stored, 8 = deflated. */
  method: number;
  compressedSize: number;
  /** Byte offset of the entry's (possibly compressed) payload within the archive. */
  dataOffset: number;
}

const LOCAL_SIG = 0x04034b50;
const CENTRAL_SIG = 0x02014b50;
const EOCD_SIG = 0x06054b50;
const FLAG_UTF8 = 0x0800;
const METHOD_STORE = 0;
const METHOD_DEFLATE = 8;
const VERSION_NEEDED = 20;
const MAX_U32 = 0xffffffff;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (const byte of buf) {
    // `& 0xff` keeps the index inside the 256-entry table, so the `?? 0` is
    // unreachable — it is there because `noUncheckedIndexedAccess` cannot see that.
    c = (CRC_TABLE[(c ^ byte) & 0xff] ?? 0) ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

/** DOS date/time is local time, two-second resolution, 1980–2107. */
function dosDateTime(d: Date): { time: number; date: number } {
  const year = Math.min(2107, Math.max(1980, d.getFullYear()));
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  const date = ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  return { time, date };
}

/**
 * Archive paths are written into an extractor's filesystem by name, so the
 * only safe names are relative, forward-slash, and free of traversal.
 */
export function checkZipPath(p: string): string {
  if (typeof p !== 'string' || p.length === 0) throw new Error('zip entry path is empty');
  if (p.includes('\\')) throw new Error(`zip entry path contains a backslash: ${p}`);
  if (p.startsWith('/')) throw new Error(`zip entry path is absolute: ${p}`);
  for (let i = 0; i < p.length; i++) {
    const code = p.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      throw new Error(`zip entry path contains a control character: ${p}`);
    }
  }
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.' || seg === '..') {
      throw new Error(`zip entry path is not a clean relative path: ${p}`);
    }
  }
  return p;
}

export function buildZip(entries: ZipEntry[], options: ZipOptions = {}): Buffer {
  if (entries.length > 0xffff)
    throw new Error('zip has more than 65535 entries; ZIP64 is not supported');
  const defaultMtime = options.mtime ?? new Date();
  const seen = new Set<string>();
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const name = checkZipPath(entry.path);
    if (seen.has(name)) throw new Error(`duplicate zip entry: ${name}`);
    seen.add(name);
    const nameBytes = Buffer.from(name, 'utf8');
    const raw = typeof entry.data === 'string' ? Buffer.from(entry.data, 'utf8') : entry.data;
    const crc = crc32(raw);

    // Deflate only when it helps; incompressible and empty payloads are stored.
    let method = METHOD_STORE;
    let body = raw;
    if (raw.length > 0) {
      const deflated = zlib.deflateRawSync(raw, { level: 9 });
      if (deflated.length < raw.length) {
        method = METHOD_DEFLATE;
        body = deflated;
      }
    }
    if (raw.length > MAX_U32 || body.length > MAX_U32) {
      throw new Error(`zip entry exceeds 4 GiB: ${name}`);
    }
    const { time, date } = dosDateTime(entry.mtime ?? defaultMtime);

    const local = Buffer.alloc(30 + nameBytes.length);
    local.writeUInt32LE(LOCAL_SIG, 0);
    local.writeUInt16LE(VERSION_NEEDED, 4);
    local.writeUInt16LE(FLAG_UTF8, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);
    nameBytes.copy(local, 30);

    const central = Buffer.alloc(46 + nameBytes.length);
    central.writeUInt32LE(CENTRAL_SIG, 0);
    central.writeUInt16LE(VERSION_NEEDED, 4); // version made by (MS-DOS attribute host)
    central.writeUInt16LE(VERSION_NEEDED, 6);
    central.writeUInt16LE(FLAG_UTF8, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt16LE(0, 30); // extra
    central.writeUInt16LE(0, 32); // comment
    central.writeUInt16LE(0, 34); // disk number start
    central.writeUInt16LE(0, 36); // internal attributes
    central.writeUInt32LE(0, 38); // external attributes
    central.writeUInt32LE(offset, 42);
    nameBytes.copy(central, 46);

    locals.push(local, body);
    centrals.push(central);
    offset += local.length + body.length;
    if (offset > MAX_U32) throw new Error('zip exceeds 4 GiB; ZIP64 is not supported');
  }

  const cdSize = centrals.reduce((n, b) => n + b.length, 0);
  if (offset + cdSize > MAX_U32) throw new Error('zip exceeds 4 GiB; ZIP64 is not supported');
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(EOCD_SIG, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...locals, ...centrals, eocd]);
}

/**
 * Parses a whole archive from memory, inflating and verifying every entry's
 * size and CRC. Sizes and CRCs come from the central directory, so archives
 * written with data descriptors (flag bit 3) by other tools read correctly too.
 * Throws on any structural problem rather than returning a partial result.
 */
export function listZip(buf: Buffer): ZipListedEntry[] {
  if (buf.length < 22) throw new Error('not a zip: too short');
  const floor = Math.max(0, buf.length - 22 - 0xffff);
  let eocd = -1;
  for (let i = buf.length - 22; i >= floor; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('not a zip: end of central directory not found');
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (cdOffset + cdSize > eocd) throw new Error('zip central directory overruns the archive');

  const out: ZipListedEntry[] = [];
  const seen = new Set<string>();
  let p = cdOffset;
  for (let i = 0; i < count; i++) {
    if (p + 46 > eocd || buf.readUInt32LE(p) !== CENTRAL_SIG) {
      throw new Error(`zip central directory entry ${i} is malformed`);
    }
    const method = buf.readUInt16LE(p + 10);
    const crc = buf.readUInt32LE(p + 16);
    const csize = buf.readUInt32LE(p + 20);
    const usize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;

    if (localOffset + 30 > cdOffset || buf.readUInt32LE(localOffset) !== LOCAL_SIG) {
      throw new Error(`zip local header for ${name} is malformed`);
    }
    const dataOffset =
      localOffset + 30 + buf.readUInt16LE(localOffset + 26) + buf.readUInt16LE(localOffset + 28);
    if (dataOffset + csize > cdOffset) {
      throw new Error(`zip data for ${name} overruns the central directory`);
    }
    const body = buf.subarray(dataOffset, dataOffset + csize);

    let data: Buffer;
    if (method === METHOD_STORE) data = Buffer.from(body);
    else if (method === METHOD_DEFLATE) data = zlib.inflateRawSync(body);
    else throw new Error(`zip entry ${name} uses unsupported compression method ${method}`);
    if (data.length !== usize) {
      throw new Error(`zip entry ${name}: size mismatch (${data.length} != ${usize})`);
    }
    if (crc32(data) !== crc) throw new Error(`zip entry ${name}: CRC mismatch`);
    if (seen.has(name)) throw new Error(`zip entry ${name} appears twice`);
    seen.add(name);
    out.push({ path: name, data, method, compressedSize: csize, dataOffset });
  }
  return out;
}

/** `listZip` as a path → content map. */
export function readZip(buf: Buffer): Map<string, Buffer> {
  return new Map(listZip(buf).map((e) => [e.path, e.data]));
}
