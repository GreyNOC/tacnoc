/** Minimal HTTP(S)-through-proxy client used by integration tests. */

import * as http from 'node:http';
import * as http2 from 'node:http2';
import * as net from 'node:net';
import * as tls from 'node:tls';

export interface ProxyResponse {
  status: number;
  rawHeaders: string[];
  body: Buffer;
}

/** Plain-HTTP request through the proxy (absolute-form request line). */
export function httpThroughProxy(
  proxyHost: string,
  proxyPort: number,
  originHost: string,
  originPort: number,
  opts: { method?: string; path?: string; headers?: Record<string, string>; body?: Buffer } = {},
): Promise<ProxyResponse> {
  const absolute = `http://${originHost}:${originPort}${opts.path ?? '/'}`;
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: proxyHost,
        port: proxyPort,
        method: opts.method ?? 'GET',
        path: absolute,
        headers: { Host: `${originHost}:${originPort}`, ...opts.headers },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c as Buffer));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            rawHeaders: res.rawHeaders,
            body: Buffer.concat(chunks),
          }),
        );
        // A mid-stream abort (proxy destroyed the response) must reject, not hang.
        res.on('aborted', () => reject(new Error('response aborted')));
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function connectTunnel(
  proxyHost: string,
  proxyPort: number,
  originHost: string,
  originPort: number,
): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const sock = net.connect(proxyPort, proxyHost, () => {
      sock.write(
        `CONNECT ${originHost}:${originPort} HTTP/1.1\r\nHost: ${originHost}:${originPort}\r\n\r\n`,
      );
    });
    let buf = Buffer.alloc(0);
    const onData = (c: Buffer): void => {
      buf = Buffer.concat([buf, c]);
      const idx = buf.indexOf('\r\n\r\n');
      if (idx === -1) return;
      sock.off('data', onData);
      const head = buf.subarray(0, idx).toString('latin1');
      if (/ 200 /.test(head)) {
        const leftover = buf.subarray(idx + 4);
        if (leftover.length) sock.unshift(leftover);
        resolve(sock);
      } else {
        reject(new Error('CONNECT failed: ' + head));
      }
    };
    sock.on('data', onData);
    sock.on('error', reject);
  });
}

/**
 * HTTPS request through the proxy. The client trusts `caPem` (the project CA):
 * a successful TLS handshake proves the MITM leaf validated against the CA.
 */
export async function httpsThroughProxy(
  proxyHost: string,
  proxyPort: number,
  caPem: string,
  originHost: string,
  originPort: number,
  opts: { method?: string; path?: string; headers?: Record<string, string>; body?: Buffer } = {},
): Promise<ProxyResponse> {
  const tunnel = await connectTunnel(proxyHost, proxyPort, originHost, originPort);
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        createConnection: () =>
          tls.connect({
            socket: tunnel,
            servername: originHost,
            ca: caPem,
          }) as unknown as net.Socket,
        method: opts.method ?? 'GET',
        path: opts.path ?? '/',
        headers: { Host: `${originHost}:${originPort}`, ...opts.headers },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c as Buffer));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? 0,
            rawHeaders: res.rawHeaders,
            body: Buffer.concat(chunks),
          }),
        );
        // A mid-stream abort (proxy destroyed the response) must reject, not hang.
        res.on('aborted', () => reject(new Error('response aborted')));
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

/** Send a plain-HTTP WebSocket upgrade through the proxy; resolve with the 101 head. */
export function wsHandshakeThroughProxy(
  proxyHost: string,
  proxyPort: number,
  originHost: string,
  originPort: number,
  path = '/ws',
): Promise<{ status: number; head: string }> {
  const absolute = `http://${originHost}:${originPort}${path}`;
  return new Promise((resolve, reject) => {
    const sock = net.connect(proxyPort, proxyHost, () => {
      sock.write(
        `GET ${absolute} HTTP/1.1\r\n` +
          `Host: ${originHost}:${originPort}\r\n` +
          'Upgrade: websocket\r\n' +
          'Connection: Upgrade\r\n' +
          'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n' +
          'Sec-WebSocket-Version: 13\r\n\r\n',
      );
    });
    let buf = Buffer.alloc(0);
    const onData = (c: Buffer): void => {
      buf = Buffer.concat([buf, c]);
      const idx = buf.indexOf('\r\n\r\n');
      if (idx === -1) return;
      sock.off('data', onData);
      const head = buf.subarray(0, idx).toString('latin1');
      const m = /HTTP\/\d\.\d\s+(\d+)/.exec(head);
      resolve({ status: m ? Number(m[1]) : 0, head });
      sock.destroy();
    };
    sock.on('data', onData);
    sock.on('error', reject);
  });
}

export interface Http2Response {
  status: number;
  body: Buffer;
}

/**
 * HTTP/2 request through the proxy. Establishes the CONNECT tunnel, negotiates
 * ALPN h2 with the proxy's leaf (trusting `caPem`), then speaks h2. A successful
 * h2 session proves the proxy intercepted HTTP/2.
 */
export async function http2ThroughProxy(
  proxyHost: string,
  proxyPort: number,
  caPem: string,
  originHost: string,
  originPort: number,
  opts: { method?: string; path?: string; headers?: Record<string, string>; body?: Buffer } = {},
): Promise<Http2Response> {
  const tunnel = await connectTunnel(proxyHost, proxyPort, originHost, originPort);
  const tlsSock = tls.connect({
    socket: tunnel,
    servername: originHost,
    ca: caPem,
    ALPNProtocols: ['h2', 'http/1.1'],
  });
  await new Promise<void>((resolve, reject) => {
    tlsSock.once('secureConnect', () => resolve());
    tlsSock.once('error', reject);
  });
  if (tlsSock.alpnProtocol !== 'h2') {
    tlsSock.destroy();
    throw new Error(`proxy did not negotiate h2 (alpn=${String(tlsSock.alpnProtocol)})`);
  }

  const client = http2.connect(`https://${originHost}:${originPort}`, {
    createConnection: () => tlsSock as unknown as net.Socket,
  });
  return new Promise<Http2Response>((resolve, reject) => {
    client.on('error', reject);
    const reqHeaders: http2.OutgoingHttpHeaders = {
      ':method': opts.method ?? 'GET',
      ':path': opts.path ?? '/',
      ...(opts.headers ?? {}),
    };
    const req = client.request(reqHeaders);
    let status = 0;
    const chunks: Buffer[] = [];
    req.on('response', (h) => {
      status = Number(h[':status'] ?? 0);
    });
    req.on('data', (c) => chunks.push(c as Buffer));
    req.on('end', () => {
      client.close();
      resolve({ status, body: Buffer.concat(chunks) });
    });
    req.on('error', reject);
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

function maskedClientTextFrame(text: string): Buffer {
  const payload = Buffer.from(text, 'utf8');
  const key = Buffer.from([0xaa, 0xbb, 0xcc, 0xdd]);
  const masked = Buffer.allocUnsafe(payload.length);
  for (let i = 0; i < payload.length; i++)
    masked[i] = (payload[i] as number) ^ (key[i % 4] as number);
  return Buffer.concat([Buffer.from([0x81, 0x80 | payload.length]), key, masked]);
}

/**
 * Full plain-HTTP WebSocket exchange through the proxy: upgrade, send one masked
 * client frame, collect server frames briefly, then close. Resolves with the raw
 * post-handshake bytes received from the server side.
 */
export function wsExchangeThroughProxy(
  proxyHost: string,
  proxyPort: number,
  originHost: string,
  originPort: number,
  clientText = 'client-frame-1',
  path = '/ws',
): Promise<Buffer> {
  const absolute = `http://${originHost}:${originPort}${path}`;
  return new Promise((resolve, reject) => {
    const sock = net.connect(proxyPort, proxyHost, () => {
      sock.write(
        `GET ${absolute} HTTP/1.1\r\n` +
          `Host: ${originHost}:${originPort}\r\n` +
          'Upgrade: websocket\r\n' +
          'Connection: Upgrade\r\n' +
          'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n' +
          'Sec-WebSocket-Version: 13\r\n\r\n',
      );
    });
    let buf = Buffer.alloc(0);
    let handshakeDone = false;
    let afterHandshake = Buffer.alloc(0);
    const onData = (c: Buffer): void => {
      buf = Buffer.concat([buf, c]);
      if (!handshakeDone) {
        const idx = buf.indexOf('\r\n\r\n');
        if (idx === -1) return;
        handshakeDone = true;
        afterHandshake = buf.subarray(idx + 4);
        sock.write(maskedClientTextFrame(clientText));
        setTimeout(() => {
          sock.destroy();
          resolve(afterHandshake);
        }, 200);
      } else {
        afterHandshake = Buffer.concat([afterHandshake, c]);
      }
    };
    sock.on('data', onData);
    sock.on('error', reject);
  });
}
