/**
 * The engagement workspace — read-only, sandboxed access to the hunting folder.
 *
 * Real engagements carry paperwork the engine cannot infer from traffic: the
 * program policy, the in-scope asset list, last quarter's report, the operator's
 * notes about what was already tried. Handing the mesh that context before it
 * plans is the difference between "fuzz whatever is in history" and "test what
 * this program actually pays for, the way this program allows".
 *
 * This module is what makes that safe to hand to a model:
 *
 *  - **Read-only.** There is no write, move, or delete. The API surface cannot
 *    modify the operator's disk.
 *  - **Contained.** Every path is resolved through `fs.realpath` and checked to
 *    be inside the workspace root. Symlinks are never followed out; `..`,
 *    absolute paths, and Windows drive-relative paths all fail the same check.
 *  - **Never the project's own secrets.** The default workspace IS the project
 *    directory, which also holds the SQLite store, the content blobs, and the
 *    file-secret-store fallback. Those are denied by name at every depth.
 *  - **Bounded.** Entry counts, recursion depth, per-file bytes, and total
 *    search work are all capped, so a deep or hostile tree cannot stall the app.
 *  - **Text only.** Binary content is refused rather than shipped to a model as
 *    mojibake.
 *
 * Everything read here is egress: it goes to the model provider. That is gated
 * upstream by the per-project egress acknowledgement, the same as captured
 * traffic.
 */

import { promises as fs } from 'node:fs';
import * as path from 'node:path';

export const MAX_ENTRIES = 2000;
export const MAX_DEPTH = 8;
export const DEFAULT_READ_BYTES = 256 * 1024;
export const MAX_READ_BYTES = 2 * 1024 * 1024;
export const MAX_SEARCH_FILES = 500;
export const MAX_SEARCH_MATCHES = 200;

/**
 * Names denied at any depth. These are the project's own internals (opening the
 * SQLite file or a content blob as "text" is useless at best) plus the places
 * secrets live: the file-secret-store fallback holds the CA private key and the
 * project data-encryption key.
 */
const DENIED_NAMES = new Set([
  'blobs',
  // The project's own CA certificate. Serving it here made an otherwise-empty
  // project directory report "1 document(s)", which read as an engagement folder
  // with material in it when there was none — and suppressed the hint pointing
  // at the folder where the material actually was. The CA has its own surface
  // (status, export, install instructions); it is not engagement material.
  'ca.pem',
  'node_modules',
  '.git',
  '.svn',
  '.hg',
  '.ssh',
  '.gnupg',
  '.aws',
  '.env',
]);

const DENIED_PATTERNS = [
  /^secrets(\.|$)/i, // FileSecretStore fallback (CA key, project DEK)
  /\.(db|db-wal|db-shm|sqlite|sqlite3)$/i,
  /^\.env(\..+)?$/i,
  /\.(key|p12|pfx|jks|keystore)$/i, // private key material
  /^id_(rsa|dsa|ecdsa|ed25519)$/i,
  /^\.npmrc$/i,
  /^\.netrc$/i,
];

/** Extensions served as text. Anything else is listed but refused for reading. */
const TEXT_EXTENSIONS = new Set([
  '.md',
  '.markdown',
  '.txt',
  '.text',
  '.json',
  '.jsonl',
  '.ndjson',
  '.yaml',
  '.yml',
  '.toml',
  '.ini',
  '.cfg',
  '.conf',
  '.csv',
  '.tsv',
  '.log',
  '.html',
  '.htm',
  '.xml',
  '.svg',
  '.har',
  '.http',
  '.rest',
  '.list',
  '.lst',
  '.pem',
  '.crt',
  '.cer',
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.tsx',
  '.jsx',
  '.py',
  '.rb',
  '.go',
  '.rs',
  '.java',
  '.php',
  '.sh',
  '.bash',
  '.ps1',
  '.sql',
  '.graphql',
  '.gql',
  '.diff',
  '.patch',
]);

/** Files most likely to carry rules of engagement, surfaced first in preflight. */
const NOTABLE_RE =
  /(policy|policies|scope|rules|roe|engagement|authoriz|program|target|asset|readme|notes|report|brief|contract|sow)/i;

export interface WorkspaceEntry {
  /** Path relative to the workspace root, always with forward slashes. */
  path: string;
  kind: 'file' | 'directory';
  size: number;
  modifiedAt: number;
  /** True when `read` will return this file's text. */
  readable: boolean;
  /** Why it is not readable (extension, size, binary). */
  reason?: string;
}

export interface WorkspaceListing {
  root: string;
  entries: WorkspaceEntry[];
  fileCount: number;
  totalBytes: number;
  /** True when the entry cap or depth cap stopped the walk before the end. */
  truncated: boolean;
  notableFiles: string[];
}

export interface WorkspaceFile {
  path: string;
  size: number;
  modifiedAt: number;
  content: string;
  /** True when the file was longer than the byte budget and was cut. */
  truncated: boolean;
}

export interface WorkspaceMatch {
  path: string;
  line: number;
  text: string;
}

export interface WorkspaceSearchResult {
  query: string;
  matches: WorkspaceMatch[];
  filesSearched: number;
  truncated: boolean;
}

/**
 * A path the caller supplied is only usable after this returns. It resolves the
 * real location on disk and proves it is inside the root — the one check that
 * stands between a model-authored string and the rest of the filesystem.
 */
export async function resolveInside(root: string, relative: string): Promise<string> {
  const realRoot = await fs.realpath(root);
  const cleaned = String(relative ?? '').replace(/\\/g, '/');
  if (cleaned.includes('\0')) throw new Error('invalid path');
  if (path.isAbsolute(cleaned) || /^[a-zA-Z]:/.test(cleaned)) {
    throw new Error(`path must be relative to the workspace root: "${relative}"`);
  }
  // An NTFS alternate data stream (`policy.md:hidden.txt`) is content no
  // directory listing shows and no folder review would ever surface. Refuse the
  // syntax outright rather than trying to reason about it.
  if (cleaned.split('/').some((segment) => segment.includes(':'))) {
    throw new Error(`"${relative}" names an alternate data stream, which is refused`);
  }
  assertNotDenied(cleaned.split('/'), relative);

  const joined = path.resolve(realRoot, cleaned);
  // Lexical containment first, so a path that plainly escapes is reported as an
  // escape rather than as "not found" — the message the operator reads should
  // say what was actually wrong.
  if (!isInside(realRoot, joined)) {
    throw new Error(`"${relative}" resolves outside the workspace root`);
  }
  // Then resolve symlinks: a link inside the root that points outside it must
  // fail too, and a lexical check alone would pass it.
  let real: string;
  try {
    real = await fs.realpath(joined);
  } catch {
    // The file may simply not exist. Resolve its PARENT only — resolving the
    // deepest existing ancestor instead would silently serve `<root>/policy.md`
    // for a request naming `no/such/dir/policy.md`, returning real content under
    // a path that does not exist. For a tool whose output becomes engagement
    // evidence, a fabricated provenance label is its own defect.
    const parent = await fs.realpath(path.dirname(joined)).catch(() => {
      throw new Error(`"${relative}" does not exist in the workspace`);
    });
    real = path.resolve(parent, path.basename(joined));
  }
  if (!isInside(realRoot, real)) {
    throw new Error(`"${relative}" resolves outside the workspace root`);
  }
  // Re-apply the denylist to the RESOLVED path. The check above saw the string
  // the caller supplied; this one sees what it actually points at. On Windows
  // the two differ whenever an 8.3 short name is used — `SECRET~1.JSO` sails
  // past a check on `secrets.enc.json` and lands on exactly that file — and a
  // hard link produces the same mismatch on any platform.
  assertNotDenied(path.relative(realRoot, real).split(path.sep), relative);
  return real;
}

/**
 * Refuse a file that is the same inode as a denied file beside it.
 *
 * Only the containing directory is scanned: a hard link must live on the same
 * volume, and the realistic case is aliasing one of the project's own internals
 * within the workspace. `nlink === 1` means no other name exists, which is the
 * common case and costs nothing.
 */
async function assertNotAliasOfDenied(
  absolute: string,
  stat: { nlink: number; ino: number; dev: number },
  reported: string,
): Promise<void> {
  if (stat.nlink <= 1 || stat.ino === 0) return;
  const dir = path.dirname(absolute);
  let names: string[];
  try {
    names = await fs.readdir(dir);
  } catch {
    return;
  }
  for (const name of names) {
    if (!isDeniedName(name)) continue;
    try {
      const other = await fs.stat(path.join(dir, name));
      if (other.ino === stat.ino && other.dev === stat.dev) {
        throw new Error(`"${reported}" is another name for a denied file ("${name}")`);
      }
    } catch (err) {
      if (err instanceof Error && err.message.includes('another name for')) throw err;
    }
  }
}

/** Throw if any segment names a denied file or directory. */
function assertNotDenied(segments: string[], reported: string): void {
  for (const segment of segments) {
    if (!segment || segment === '.') continue;
    if (isDeniedName(segment)) {
      throw new Error(`"${reported}" is inside a denied area of the workspace`);
    }
  }
}

function isInside(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function isDeniedName(name: string): boolean {
  const lower = name.toLowerCase();
  if (DENIED_NAMES.has(lower)) return true;
  return DENIED_PATTERNS.some((re) => re.test(name));
}

function readability(name: string, size: number): { readable: boolean; reason?: string } {
  const ext = path.extname(name).toLowerCase();
  if (ext === '.pdf') {
    return {
      readable: false,
      reason: 'PDF: export the policy to .txt or .md to make it readable here',
    };
  }
  if (!TEXT_EXTENSIONS.has(ext)) {
    return { readable: false, reason: ext ? `unsupported type "${ext}"` : 'no file extension' };
  }
  if (size > MAX_READ_BYTES) {
    return { readable: false, reason: `larger than the ${MAX_READ_BYTES / 1024} KiB read limit` };
  }
  return { readable: true };
}

/** Recursively list the workspace. Never follows symlinks, never leaves the root. */
export async function listWorkspace(
  root: string,
  options: { maxEntries?: number; maxDepth?: number } = {},
): Promise<WorkspaceListing> {
  const realRoot = await fs.realpath(root);
  const maxEntries = clamp(options.maxEntries ?? MAX_ENTRIES, 1, MAX_ENTRIES);
  const maxDepth = clamp(options.maxDepth ?? MAX_DEPTH, 1, MAX_DEPTH);
  const entries: WorkspaceEntry[] = [];
  let fileCount = 0;
  let totalBytes = 0;
  let truncated = false;

  /** True once the entry cap is hit — the only condition that ends the walk. */
  let exhausted = false;

  const walk = async (dir: string, depth: number): Promise<void> => {
    if (exhausted) return;
    if (depth > maxDepth) {
      // Too deep is a fact about THIS branch, not a reason to abandon the rest
      // of the tree. Treating it as a global stop meant one over-deep folder
      // hid every later sibling — including the scope document — and the mesh
      // then answered "is this host in scope?" from an authoritative-looking
      // empty listing while the operator's written prohibition sat unread.
      truncated = true;
      return;
    }
    let dirents;
    try {
      dirents = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return; // unreadable subtree: report what we can rather than failing the listing
    }
    dirents.sort((a, b) => a.name.localeCompare(b.name));
    for (const dirent of dirents) {
      if (entries.length >= maxEntries) {
        truncated = true;
        exhausted = true;
        return;
      }
      if (isDeniedName(dirent.name)) continue;
      // Symlinks are skipped outright. Following one is the classic way out of a
      // sandbox, and an engagement folder has no legitimate need for them.
      if (dirent.isSymbolicLink()) continue;
      const absolute = path.join(dir, dirent.name);
      const relative = path.relative(realRoot, absolute).replace(/\\/g, '/');
      let stat;
      try {
        stat = await fs.stat(absolute);
      } catch {
        continue;
      }
      if (dirent.isDirectory()) {
        entries.push({
          path: relative,
          kind: 'directory',
          size: 0,
          modifiedAt: stat.mtimeMs,
          readable: false,
        });
        await walk(absolute, depth + 1);
      } else if (dirent.isFile()) {
        fileCount += 1;
        totalBytes += stat.size;
        entries.push({
          path: relative,
          kind: 'file',
          size: stat.size,
          modifiedAt: stat.mtimeMs,
          ...readability(dirent.name, stat.size),
        });
      }
    }
  };

  await walk(realRoot, 1);
  const notableFiles = entries
    .filter((e) => e.kind === 'file' && e.readable && NOTABLE_RE.test(e.path))
    .sort((a, b) => b.modifiedAt - a.modifiedAt)
    .slice(0, 25)
    .map((e) => e.path);

  return { root: realRoot, entries, fileCount, totalBytes, truncated, notableFiles };
}

/** Read one workspace file as text. Refuses binaries and anything outside the root. */
export async function readWorkspaceFile(
  root: string,
  relative: string,
  maxBytes = DEFAULT_READ_BYTES,
): Promise<WorkspaceFile> {
  const absolute = await resolveInside(root, relative);
  // Open first, then stat the HANDLE. Resolving a path and re-opening it by name
  // leaves a window in which the leaf can be swapped for a link to somewhere
  // else, and the second lookup would follow it.
  const handle = await fs.open(absolute, 'r');
  try {
    const stat = await handle.stat();
    if (!stat.isFile()) throw new Error(`"${relative}" is not a file`);
    // A hard link is a second NAME for the same file, and `realpath` cannot see
    // through it — `inventory.json` linked to `secrets.json` passes every
    // path-based check. Compare identity, not spelling: if this file IS a denied
    // file in the same directory, refuse it.
    await assertNotAliasOfDenied(absolute, stat, relative);
    const name = path.basename(absolute);
    const check = readability(name, stat.size);
    if (!check.readable) throw new Error(`"${relative}" cannot be read as text — ${check.reason}`);

    const budget = clamp(maxBytes, 1, MAX_READ_BYTES);
    const buffer = Buffer.alloc(Math.min(budget, stat.size));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    const bytes = buffer.subarray(0, bytesRead);
    // Scan everything being returned, not a prefix of it. A file with a long
    // text preamble and binary after it would otherwise ship whole.
    if (bytes.includes(0)) {
      throw new Error(`"${relative}" looks like binary content, not text`);
    }
    // Private key material is refused by content, not by extension: `.pem` is
    // both the usual certificate extension and the usual private-key one, and
    // a key can be pasted into any file. This runs before the content is
    // returned, so it is refused before it can be egressed.
    const text = bytes.toString('utf8');
    if (/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(text)) {
      throw new Error(
        `"${relative}" contains private key material and will not be read into an AI context`,
      );
    }
    return {
      path: relative.replace(/\\/g, '/'),
      size: stat.size,
      modifiedAt: stat.mtimeMs,
      content: text,
      truncated: stat.size > bytes.length,
    };
  } finally {
    await handle.close();
  }
}

/**
 * Case-insensitive substring search across readable workspace files. Deliberately
 * not a regex: a model-authored pattern is a denial-of-service lever on this
 * process, and substring search answers "where is this host / handle / endpoint
 * mentioned" just as well.
 */
export async function searchWorkspace(
  root: string,
  query: string,
  options: { maxMatches?: number; maxFiles?: number } = {},
): Promise<WorkspaceSearchResult> {
  const needle = String(query ?? '').trim();
  if (!needle) throw new Error('search query is empty');
  const maxMatches = clamp(options.maxMatches ?? 50, 1, MAX_SEARCH_MATCHES);
  const maxFiles = clamp(options.maxFiles ?? MAX_SEARCH_FILES, 1, MAX_SEARCH_FILES);
  const listing = await listWorkspace(root);
  const lowered = needle.toLowerCase();
  const matches: WorkspaceMatch[] = [];
  let filesSearched = 0;
  let truncated = listing.truncated;

  for (const entry of listing.entries) {
    if (entry.kind !== 'file' || !entry.readable) continue;
    if (filesSearched >= maxFiles) {
      truncated = true;
      break;
    }
    if (matches.length >= maxMatches) {
      truncated = true;
      break;
    }
    filesSearched += 1;
    let file: WorkspaceFile;
    try {
      file = await readWorkspaceFile(root, entry.path);
    } catch {
      continue; // binary or unreadable: skip, don't fail the whole search
    }
    const lines = file.content.split(/\r?\n/);
    for (let i = 0; i < lines.length; i += 1) {
      if (matches.length >= maxMatches) {
        truncated = true;
        break;
      }
      const line = lines[i]!;
      if (line.toLowerCase().includes(lowered)) {
        matches.push({
          path: entry.path,
          line: i + 1,
          text: line.length > 400 ? `${line.slice(0, 400)}…` : line,
        });
      }
    }
  }
  return { query: needle, matches, filesSearched, truncated };
}

function clamp(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.trunc(value)));
}
