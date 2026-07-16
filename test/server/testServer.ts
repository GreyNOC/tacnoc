/**
 * Deliberately-safe local test server.
 *
 * Serves a fixed set of endpoints exercising the proxy and scanner: chunked,
 * gzip, binary, large, duplicate/oddly-cased headers, insecure cookies, missing
 * security headers, reflected input, verbose errors, banners, and a minimal
 * WebSocket handshake. NOTHING here talks to the internet; tests never depend on
 * public targets.
 */

import * as http from 'node:http';
import * as https from 'node:https';
import * as net from 'node:net';
import * as zlib from 'node:zlib';
import * as crypto from 'node:crypto';
import { makeSelfSigned } from './selfSignedCert.js';

export interface TestServerHandle {
  httpPort: number;
  httpsPort: number;
  httpsCertPem: string;
  close: () => Promise<void>;
}

function route(req: http.IncomingMessage, res: http.ServerResponse): void {
  const url = new URL(req.url ?? '/', 'http://internal.test');
  const path = url.pathname;

  if (path === '/json') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, ts: 0 }));
    return;
  }

  if (path === '/echo-body') {
    const chunks: Buffer[] = [];
    req.on('data', (c) => chunks.push(c as Buffer));
    req.on('end', () => {
      const body = Buffer.concat(chunks);
      res.writeHead(200, {
        'Content-Type': req.headers['content-type'] ?? 'application/octet-stream',
        'X-Echo-Length': String(body.length),
      });
      res.end(body);
    });
    return;
  }

  if (path === '/chunked') {
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Transfer-Encoding': 'chunked' });
    res.write('part1-');
    setTimeout(() => {
      res.write('part2-');
      res.end('part3');
    }, 5);
    return;
  }

  if (path === '/gzip') {
    const payload = zlib.gzipSync(Buffer.from('gzipped-payload-'.repeat(8)));
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Content-Encoding': 'gzip' });
    res.end(payload);
    return;
  }

  if (path === '/binary') {
    const buf = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0x10, 0x00, 0x7f]);
    res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
    res.end(buf);
    return;
  }

  if (path === '/large') {
    const size = Math.min(Number(url.searchParams.get('size') ?? '1024'), 50 * 1024 * 1024);
    res.writeHead(200, { 'Content-Type': 'application/octet-stream' });
    res.end(Buffer.alloc(size, 0x41));
    return;
  }

  if (path === '/set-cookie') {
    res.writeHead(200, {
      'Content-Type': 'text/plain',
      // duplicate Set-Cookie headers with an insecure one for the scanner
      'Set-Cookie': ['sid=SECRETVALUE; Path=/', 'tracker=1; Path=/'],
    });
    res.end('cookies set');
    return;
  }

  if (path === '/dup-headers') {
    res.setHeader('X-Dup', ['a', 'b']);
    res.setHeader('Content-Type', 'text/plain');
    // Odd casing preserved by Node for outgoing where possible.
    res.setHeader('x-Weird-CASE', 'yes');
    res.writeHead(200);
    res.end('dup');
    return;
  }

  if (path === '/missing-headers') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<p>no security headers here</p>');
    return;
  }

  if (path === '/secure-headers') {
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Content-Security-Policy': "default-src 'self'",
      'X-Content-Type-Options': 'nosniff',
      'Strict-Transport-Security': 'max-age=63072000',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'no-referrer',
    });
    res.end('<p>secured</p>');
    return;
  }

  if (path === '/reflect') {
    const q = url.searchParams.get('q') ?? '';
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<html><body>You searched for: ${q}</body></html>`);
    return;
  }

  if (path === '/error') {
    res.writeHead(500, { 'Content-Type': 'text/plain' });
    res.end(
      'Exception: NullReferenceException at Server.Handler.process (server.js:42:13)\n stack trace',
    );
    return;
  }

  if (path === '/banner') {
    res.writeHead(200, {
      'Content-Type': 'text/plain',
      Server: 'TestServer/9.9.9 (Unix) OpenTest/1.0',
    });
    res.end('banner');
    return;
  }

  if (path === '/secret-in-body') {
    res.writeHead(200, { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store' });
    res.end('leak AKIAIOSFODNN7EXAMPLE and token eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig here');
    return;
  }

  if (path === '/redirect') {
    res.writeHead(302, { Location: '/json' });
    res.end();
    return;
  }

  if (path === '/slow-body') {
    // Send headers + a partial body, then hang forever (never end) so the proxy
    // hits its upstream timeout MID-STREAM.
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.write('partial-body-');
    // deliberately no res.end() and no further writes
    return;
  }

  // default echo of request metadata
  const chunks: Buffer[] = [];
  req.on('data', (c) => chunks.push(c as Buffer));
  req.on('end', () => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        method: req.method,
        url: req.url,
        headers: req.rawHeaders,
        bodyLength: Buffer.concat(chunks).length,
      }),
    );
  });
}

/** Build an unmasked (server→client) text frame. */
export function serverTextFrame(text: string): Buffer {
  const payload = Buffer.from(text, 'utf8');
  const len = payload.length;
  const header = len < 126 ? Buffer.from([0x81, len]) : Buffer.alloc(0);
  return Buffer.concat([header, payload]);
}

/** Minimal WebSocket handshake (RFC 6455) that then sends two server frames. */
function handleUpgrade(req: http.IncomingMessage, socket: net.Socket): void {
  const key = req.headers['sec-websocket-key'];
  if (typeof key !== 'string') {
    socket.destroy();
    return;
  }
  const accept = crypto
    .createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
      'Upgrade: websocket\r\n' +
      'Connection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );
  // Send two server→client frames so frame capture can be verified.
  socket.write(serverTextFrame('server-frame-1'));
  socket.write(serverTextFrame('server-frame-2'));
  socket.on('data', () => {
    /* consume/ignore client frames */
  });
}

export async function startTestServer(): Promise<TestServerHandle> {
  // Track upgraded (WebSocket) sockets so they can be force-closed on shutdown;
  // upgraded sockets are detached and are not reaped by closeAllConnections().
  const upgradeSockets = new Set<net.Socket>();
  const trackUpgrade = (req: http.IncomingMessage, sock: net.Socket): void => {
    upgradeSockets.add(sock);
    sock.on('close', () => upgradeSockets.delete(sock));
    handleUpgrade(req, sock);
  };

  const httpServer = http.createServer(route);
  httpServer.on('upgrade', (req, sock) => trackUpgrade(req, sock as net.Socket));

  const { key, cert } = makeSelfSigned('localhost');
  const httpsServer = https.createServer({ key, cert }, route);
  httpsServer.on('upgrade', (req, sock) => trackUpgrade(req, sock as net.Socket));

  await Promise.all([
    new Promise<void>((r) => httpServer.listen(0, '127.0.0.1', r)),
    new Promise<void>((r) => httpsServer.listen(0, '127.0.0.1', r)),
  ]);

  return {
    httpPort: (httpServer.address() as net.AddressInfo).port,
    httpsPort: (httpsServer.address() as net.AddressInfo).port,
    httpsCertPem: cert,
    close: async () => {
      for (const s of upgradeSockets) s.destroy();
      upgradeSockets.clear();
      httpServer.closeAllConnections?.();
      httpsServer.closeAllConnections?.();
      await Promise.all([
        new Promise<void>((r) => httpServer.close(() => r())),
        new Promise<void>((r) => httpsServer.close(() => r())),
      ]);
    },
  };
}
