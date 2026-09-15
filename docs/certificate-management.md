# Certificate management (TLS interception)

To read HTTPS traffic, TACNOC terminates TLS locally with certificates
signed by a **project-scoped Certificate Authority (CA)** it generates on your
machine. This is powerful and requires your explicit, informed consent.

## How it works

- On first project open, a CA key pair + self-signed CA certificate are
  generated locally with `node-forge` (RSA-3072 CA, SHA-256).
- The **CA private key is stored in OS secure storage** via Electron
  `safeStorage` (DPAPI on Windows, Keychain on macOS, libsecret on Linux). In
  headless/test contexts a clearly-labeled, obfuscation-grade file fallback is
  used instead (`isSecure()` reports which).
- The **public CA certificate** is written to `ca.pem` in the project folder and
  is safe to share/install.
- When a browser sends `CONNECT host:port`, the proxy answers `200`, then
  presents a **per-host leaf certificate** (RSA-2048, ~397-day validity, SAN =
  the host) signed by the CA. Leaf certs are minted on demand and cached; a
  single leaf key pair is reused across hosts for speed.

Verified: leaf certs validate against the CA over a real TLS handshake (see
`test/engine/ca.test.ts`) and the proxy decrypts/re-encrypts HTTPS end to end
(`test/engine/proxy.test.ts`).

## Trusting the CA — optional, guided, and always your decision

**This step is optional.** Plain `http://` traffic is captured with no
certificate at all, and a project is fully usable without ever installing one.
You only need it to read `https://`.

The app **never modifies your operating system's trust store.** The
**CA Certificate** view walks you through it in four steps and hands you the
command to run yourself:

1. **Save the certificate to a file.** You acknowledge the risk first; the
   private key never leaves OS secure storage.
2. **Trust it.** The view shows the exact command for your platform, with the
   saved path already quoted for your shell, plus the by-hand equivalent if you
   would rather see each dialog. The **removal** command is shown next to it, not
   in a footnote.
3. **Point your browser at the proxy** — both HTTP *and* HTTPS. A browser that
   proxies only HTTP never sends the `CONNECT` that interception depends on.
4. **Check that it worked.** See below — this step reads evidence, not settings.

The commands the guide gives you, by platform:

| Platform | Install | Remove |
|---|---|---|
| Windows | `certutil -addstore -user Root <file>` | `certutil -delstore -user Root "TACNOC Project CA"` |
| macOS | `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db <file>` | `security delete-certificate -c "TACNOC Project CA"` |
| Linux (Chrome/Chromium) | `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "TACNOC Project CA" -i <file>` | `certutil -d sql:$HOME/.pki/nssdb -D -n "TACNOC Project CA"` |

Each of these deliberately takes the **narrowest trust that works**: the current
user rather than the machine, the login keychain rather than the System keychain,
the browser's own NSS store rather than the system CA bundle. None of them needs
administrator rights, which is the point — a step that demands elevation is a
step that gets run in the wrong scope.

**Firefox and Tor Browser keep their own certificate stores** and ignore the OS
one entirely. Import the file at *Settings → Privacy & Security → Certificates →
View Certificates → Authorities → Import* and tick *Trust this CA to identify
websites*. This is the single most common reason a correct-looking install
captures nothing.

### Verifying it actually works

The guide's last step counts **HTTPS exchanges the proxy decrypted**. It counts
proxy traffic only: Repeater and Variation requests travel over the engine's own
TLS stack, never present the project's leaf certificate to anything, and succeed
whether or not any client trusts the CA — so counting them would let a single
engine-generated probe report success over a browser that was still refusing
every intercepted connection. The same number backs the `ca-trust` check in
[preflight](engagement-and-hunting.md).

### Strong recommendations

- Install the CA **only** into the browser/profile you use for the engagement —
  ideally a dedicated testing profile.
- **Remove trust when you are finished.** A trusted interception CA is a
  standing risk if the key is ever exposed. The removal command sits beside the
  install command in the guide for exactly this reason.
- Never share the CA **private** key. Only the public certificate is meant to be
  distributed, and only to systems you control for testing.

## HTTP/2, HTTP/3, and downgrade behavior (important)

**HTTP/2 interception IS implemented. HTTP/3 / QUIC is NOT.**

- The MITM is an HTTP/2 secure server (`http2.createSecureServer` with
  `allowHTTP1`). It advertises ALPN **`h2` and `http/1.1`**, so h2-capable
  clients are intercepted as HTTP/2 and http/1.1 clients as HTTP/1.1 — both
  through the same request path.
- HTTP/2 requests are **translated to HTTP/1.1 to the origin** (pseudo-headers
  stripped, `Host` synthesized from `:authority`), which lets interception work
  against any origin regardless of the origin's own protocol. Captured exchanges
  are labeled `HTTP/2`. Note that HTTP/2 mandates lowercase header names, so
  header casing is normalized by the protocol on the h2 leg (not a fidelity loss
  introduced by the proxy).
- You can disable h2 interception (offer only `http/1.1`) via the engine config
  flag `interceptHttp2: false`, in which case h2 clients downgrade to HTTP/1.1.
- **QUIC / HTTP/3 is not handled.** Clients generally fall back to h2/h1 when h3
  fails; if a client insists on h3, disable HTTP/3 in the browser to route that
  traffic through the proxy.

## Origin certificate validation

When connecting to the true origin, the proxy currently does **not** hard-fail on
invalid origin certificates (so testing against self-signed/lab origins is
possible). Certificate/hostname problems observed by the Repeater are surfaced in
its TLS panel, and a "credentials over cleartext HTTP" passive check flags
plaintext credential transmission. Treat origin-trust decisions as your
responsibility during an engagement.
