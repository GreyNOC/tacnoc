/**
 * Minimal cookie jar for the repeater. Not a full RFC 6265 implementation:
 * it stores name=value pairs per host and applies them on same-host requests.
 * It tracks the Secure attribute so Secure cookies are not replayed over
 * cleartext HTTP, and detects deletion via Max-Age<=0 or an Expires date in the
 * past. Path/Domain are parsed-but-not-enforced, which is sufficient for the
 * manual resend workflow.
 */

export interface StoredCookie {
  name: string;
  value: string;
  host: string;
  /** True when the cookie was set with the Secure attribute. */
  secure: boolean;
}

interface JarEntry {
  value: string;
  secure: boolean;
}

export class CookieJar {
  private readonly byHost = new Map<string, Map<string, JarEntry>>();

  /** Ingest Set-Cookie header values from a response. */
  ingest(host: string, setCookieValues: readonly string[]): void {
    const jar = this.byHost.get(host) ?? new Map<string, JarEntry>();
    for (const sc of setCookieValues) {
      const firstPair = sc.split(';', 1)[0] ?? '';
      const eq = firstPair.indexOf('=');
      if (eq <= 0) continue;
      const name = firstPair.slice(0, eq).trim();
      const value = firstPair.slice(eq + 1).trim();
      if (isDeletion(sc)) {
        jar.delete(name);
      } else {
        jar.set(name, { value, secure: /;\s*secure\b/i.test(sc) });
      }
    }
    this.byHost.set(host, jar);
  }

  /**
   * Build a Cookie header value for a host, or undefined if none apply.
   * Secure cookies are omitted for non-https requests so a Secure cookie set
   * over HTTPS is never replayed over cleartext after an https→http redirect.
   */
  cookieHeader(host: string, scheme: string = 'https'): string | undefined {
    const jar = this.byHost.get(host);
    if (!jar || jar.size === 0) return undefined;
    const overHttps = scheme === 'https';
    const parts = [...jar.entries()]
      .filter(([, c]) => overHttps || !c.secure)
      .map(([n, c]) => `${n}=${c.value}`);
    return parts.length ? parts.join('; ') : undefined;
  }

  list(): StoredCookie[] {
    const out: StoredCookie[] = [];
    for (const [host, jar] of this.byHost) {
      for (const [name, c] of jar) out.push({ name, value: c.value, host, secure: c.secure });
    }
    return out;
  }

  clear(): void {
    this.byHost.clear();
  }
}

/** True when a Set-Cookie represents a deletion (Max-Age<=0 or past Expires). */
function isDeletion(setCookie: string): boolean {
  const maxAge = /;\s*max-age=\s*(-?\d+)/i.exec(setCookie);
  if (maxAge) return Number(maxAge[1]) <= 0;
  const expires = /;\s*expires=([^;]+)/i.exec(setCookie);
  if (expires && expires[1]) {
    // Accept both the space form ("Thu, 01 Jan 1970 …") and the common
    // hyphenated form ("Thu, 01-Jan-1970 …") by normalizing dashes to spaces.
    const t = Date.parse(expires[1].trim().replace(/-/g, ' '));
    if (Number.isFinite(t)) return t <= Date.now();
  }
  return false;
}
