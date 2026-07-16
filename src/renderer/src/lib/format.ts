/** Renderer-side formatting helpers. Pure, no engine access. */

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function b64ToText(b64: string): string {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(b64ToBytes(b64));
  } catch {
    return '';
  }
}

export function textToB64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = '';
  for (const byte of bytes) bin += String.fromCharCode(byte);
  return btoa(bin);
}

/** Classic hex dump (offset | hex | ascii). */
export function hexdump(bytes: Uint8Array, maxBytes = 64 * 1024): string {
  const n = Math.min(bytes.length, maxBytes);
  const lines: string[] = [];
  for (let i = 0; i < n; i += 16) {
    const slice = bytes.subarray(i, i + 16);
    const hex = [...slice].map((byteVal) => byteVal.toString(16).padStart(2, '0')).join(' ');
    const ascii = [...slice]
      .map((c) => (c >= 32 && c < 127 ? String.fromCharCode(c) : '.'))
      .join('');
    lines.push(`${i.toString(16).padStart(8, '0')}  ${hex.padEnd(47)}  ${ascii}`);
  }
  if (bytes.length > n) lines.push(`… (${bytes.length - n} more bytes)`);
  return lines.join('\n');
}

export function tryPrettyJson(text: string): string | null {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return null;
  }
}

export function statusClass(status?: number): string {
  if (!status) return '';
  return `status-${Math.floor(status / 100)}`;
}

export function bytesHuman(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function timeShort(ts: number): string {
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}
