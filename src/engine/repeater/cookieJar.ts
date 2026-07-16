/**
 * Minimal cookie jar for the repeater. Not a full RFC 6265 implementation:
 * it stores name=value pairs per host and applies them on same-host requests.
 * Attributes (Path/Domain/Secure/expiry) are parsed but only Domain/host
 * scoping is enforced, which is sufficient for manual resend workflows.
 */

export interface StoredCookie {
  name: string;
  value: string;
  host: string;
}

export class CookieJar {
  private readonly byHost = new Map<string, Map<string, string>>();

  /** Ingest Set-Cookie header values from a response. */
  ingest(host: string, setCookieValues: readonly string[]): void {
    const jar = this.byHost.get(host) ?? new Map<string, string>();
    for (const sc of setCookieValues) {
      const firstPair = sc.split(';', 1)[0] ?? '';
      const eq = firstPair.indexOf('=');
      if (eq <= 0) continue;
      const name = firstPair.slice(0, eq).trim();
      const value = firstPair.slice(eq + 1).trim();
      if (/;\s*max-age=0\b/i.test(sc) || /;\s*expires=Thu, 01 Jan 1970/i.test(sc)) {
        jar.delete(name);
      } else {
        jar.set(name, value);
      }
    }
    this.byHost.set(host, jar);
  }

  /** Build a Cookie header value for a host, or undefined if none. */
  cookieHeader(host: string): string | undefined {
    const jar = this.byHost.get(host);
    if (!jar || jar.size === 0) return undefined;
    return [...jar.entries()].map(([n, v]) => `${n}=${v}`).join('; ');
  }

  list(): StoredCookie[] {
    const out: StoredCookie[] = [];
    for (const [host, jar] of this.byHost) {
      for (const [name, value] of jar) out.push({ name, value, host });
    }
    return out;
  }

  clear(): void {
    this.byHost.clear();
  }
}
