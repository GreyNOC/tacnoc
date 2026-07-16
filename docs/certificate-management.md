# Certificate management (TLS interception)

To read HTTPS traffic, GreyNOC Belcher terminates TLS locally with certificates
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

## Trusting the CA — an explicit, warned, manual step

The app **never modifies your operating system's trust store.** In the
**CA Certificate** view you must acknowledge the risk, then save the certificate
to a file and install it yourself:

- **Windows:** import the `.crt` into *Trusted Root Certification Authorities*
  for the **current user** (`certmgr.msc` → Trusted Root → All Tasks → Import).
- **macOS:** open the `.pem` in *Keychain Access* (login keychain) and set it to
  *Always Trust*.
- **Linux:** install the `.pem` into your **browser's** certificate store
  (browsers typically manage their own trust); avoid system-wide trust.

### Strong recommendations

- Install the CA **only** into the browser/profile you use for the engagement —
  ideally a dedicated testing profile.
- **Remove trust when you are finished.** A trusted interception CA is a
  standing risk if the key is ever exposed.
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
