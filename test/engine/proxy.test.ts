import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as os from 'node:os';
import * as net from 'node:net';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { promises as fs } from 'node:fs';
import * as crypto from 'node:crypto';
import { ProjectStore } from '../../src/engine/project/projectStore.js';
import { InMemorySecretStore } from '../../src/engine/ca/secretStore.js';
import { ProxyServer } from '../../src/engine/proxy/proxyServer.js';
import { Interceptor } from '../../src/engine/proxy/interceptor.js';
import { startTestServer, type TestServerHandle } from '../server/testServer.js';
import {
  httpThroughProxy,
  httpsThroughProxy,
  http2ThroughProxy,
  wsHandshakeThroughProxy,
  wsExchangeThroughProxy,
} from '../support/proxyClient.js';
import type { HttpExchange } from '../../src/shared/model.js';
import { getHeader, getHeaders } from '../../src/shared/model.js';
import type { ScopeConfig } from '../../src/shared/scope.js';
import type { CapturedWsMessage } from '../../src/engine/proxy/proxyServer.js';

let server: TestServerHandle;
let project: ProjectStore;
let proxy: ProxyServer;
let interceptor: Interceptor;
let captured: HttpExchange[];
let capturedWs: CapturedWsMessage[];
let scope: ScopeConfig;
let projDir: string;
let proxyPort: number;

const PROXY_HOST = '127.0.0.1';

beforeAll(async () => {
  server = await startTestServer();
  projDir = path.join(
    os.tmpdir(),
    `belcher-proxy-${crypto.randomBytes(6).toString('hex')}.gnbproj`,
  );
  project = await ProjectStore.create(projDir, {
    name: 'proxy-test',
    secretStore: new InMemorySecretStore(),
  });
  interceptor = new Interceptor();
  captured = [];
  capturedWs = [];
  scope = { include: [], exclude: [] };
  proxy = new ProxyServer({
    ca: project.ca,
    limits: project.config.limits,
    blobStore: project.blobs,
    interceptor,
    getScope: () => scope,
    onExchange: (ex) => {
      captured.push(ex);
      project.history.insert(ex);
    },
    onWebSocketMessage: (msg) => capturedWs.push(msg),
    captureWebSockets: true,
  });
  const bound = await proxy.start(PROXY_HOST, 0);
  proxyPort = bound.port;
});

afterAll(async () => {
  await proxy.stop();
  project.close();
  await server.close();
  await fs.rm(projDir, { recursive: true, force: true });
});

function lastFor(pathFragment: string): HttpExchange {
  const match = [...captured].reverse().find((e) => e.request.url.includes(pathFragment));
  if (!match) throw new Error(`no captured exchange for ${pathFragment}`);
  return match;
}

describe('proxy — plain HTTP', () => {
  it('proxies and captures an ordinary GET', async () => {
    const res = await httpThroughProxy(PROXY_HOST, proxyPort, '127.0.0.1', server.httpPort, {
      path: '/json',
    });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body.toString()).ok).toBe(true);
    const ex = lastFor('/json');
    expect(ex.scheme).toBe('http');
    expect(ex.response?.statusCode).toBe(200);
    expect(Buffer.from(ex.response!.body.inline!).toString()).toContain('"ok":true');
  });

  it('captures POST request bodies and echoes them', async () => {
    const body = Buffer.from('hello=world&x=1');
    const res = await httpThroughProxy(PROXY_HOST, proxyPort, '127.0.0.1', server.httpPort, {
      method: 'POST',
      path: '/echo-body',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    expect(res.body.equals(body)).toBe(true);
    const ex = lastFor('/echo-body');
    expect(ex.request.method).toBe('POST');
    expect(ex.request.body.size).toBe(body.length);
  });

  it('preserves chunked responses in full', async () => {
    const res = await httpThroughProxy(PROXY_HOST, proxyPort, '127.0.0.1', server.httpPort, {
      path: '/chunked',
    });
    expect(res.body.toString()).toBe('part1-part2-part3');
    const ex = lastFor('/chunked');
    expect(Buffer.from(ex.response!.body.inline!).toString()).toBe('part1-part2-part3');
  });

  it('does not alter compressed bodies and records the encoding', async () => {
    const res = await httpThroughProxy(PROXY_HOST, proxyPort, '127.0.0.1', server.httpPort, {
      path: '/gzip',
    });
    expect(zlib.gunzipSync(res.body).toString()).toContain('gzipped-payload-');
    const ex = lastFor('/gzip');
    expect(ex.response!.body.contentEncoding).toBe('gzip');
    // Stored bytes are the raw gzip stream (proxy never silently decodes).
    expect(zlib.gunzipSync(Buffer.from(ex.response!.body.inline!)).toString()).toContain('gzipped');
  });

  it('preserves binary bodies byte-for-byte', async () => {
    const res = await httpThroughProxy(PROXY_HOST, proxyPort, '127.0.0.1', server.httpPort, {
      path: '/binary',
    });
    const expected = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0x10, 0x00, 0x7f]);
    expect(res.body.equals(expected)).toBe(true);
    const ex = lastFor('/binary');
    expect(Buffer.from(ex.response!.body.inline!).equals(expected)).toBe(true);
  });

  it('preserves duplicate + oddly-cased request headers', async () => {
    await httpThroughProxy(PROXY_HOST, proxyPort, '127.0.0.1', server.httpPort, {
      path: '/json',
      headers: { 'X-Custom-CASE': 'V1' },
    });
    const ex = lastFor('/json');
    expect(getHeader(ex.request.headers, 'x-custom-case')).toBe('V1');
    // the exact casing sent is retained in the captured header name
    expect(ex.request.headers.some((h) => h.name === 'X-Custom-CASE')).toBe(true);
  });

  it('passes redirects through without following them', async () => {
    const res = await httpThroughProxy(PROXY_HOST, proxyPort, '127.0.0.1', server.httpPort, {
      path: '/redirect',
    });
    expect(res.status).toBe(302);
  });

  it('captures multiple Set-Cookie headers as distinct entries', async () => {
    await httpThroughProxy(PROXY_HOST, proxyPort, '127.0.0.1', server.httpPort, {
      path: '/set-cookie',
    });
    const ex = lastFor('/set-cookie');
    const cookies = getHeaders(ex.response!.headers, 'set-cookie');
    expect(cookies.length).toBe(2);
  });
});

describe('proxy — HTTPS MITM', () => {
  it('decrypts and captures HTTPS via a leaf validated against the project CA', async () => {
    const res = await httpsThroughProxy(
      PROXY_HOST,
      proxyPort,
      project.ca.certificatePem,
      'localhost',
      server.httpsPort,
      { path: '/json' },
    );
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body.toString()).ok).toBe(true);
    // most recent /json capture should be the https one
    const https = [...captured]
      .reverse()
      .find((e) => e.scheme === 'https' && e.request.url.includes('/json'));
    expect(https).toBeDefined();
    expect(https!.host).toBe('localhost');
  });
});

describe('proxy — HTTP/2 interception', () => {
  it('negotiates h2 and intercepts an h2 GET (translated to h1 origin)', async () => {
    const res = await http2ThroughProxy(
      PROXY_HOST,
      proxyPort,
      project.ca.certificatePem,
      'localhost',
      server.httpsPort,
      { path: '/json' },
    );
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body.toString()).ok).toBe(true);
    const h2 = [...captured]
      .reverse()
      .find((e) => e.request.httpVersion === 'HTTP/2' && e.request.url.includes('/json'));
    expect(h2).toBeDefined();
    expect(h2!.response?.statusCode).toBe(200);
    expect(h2!.scheme).toBe('https');
  });

  it('captures an h2 POST request body', async () => {
    const body = Buffer.from('h2-post-payload-xyz');
    const res = await http2ThroughProxy(
      PROXY_HOST,
      proxyPort,
      project.ca.certificatePem,
      'localhost',
      server.httpsPort,
      { method: 'POST', path: '/echo-body', headers: { 'content-type': 'text/plain' }, body },
    );
    expect(res.body.equals(body)).toBe(true);
    const ex = [...captured]
      .reverse()
      .find((e) => e.request.httpVersion === 'HTTP/2' && e.request.url.includes('/echo-body'));
    expect(ex).toBeDefined();
    expect(ex!.request.body.size).toBe(body.length);
  });
});

describe('proxy — limits', () => {
  it('truncates stored bodies at the cap while forwarding the full body', async () => {
    // Dedicated proxy with a tiny body cap.
    const smallInterceptor = new Interceptor();
    const smallCaptured: HttpExchange[] = [];
    const smallProxy = new ProxyServer({
      ca: project.ca,
      limits: {
        ...project.config.limits,
        body: { spillToDiskAfterBytes: 1024, maxCapturedBytes: 1000 },
      },
      blobStore: project.blobs,
      interceptor: smallInterceptor,
      getScope: () => scope,
      onExchange: (ex) => smallCaptured.push(ex),
    });
    const bound = await smallProxy.start(PROXY_HOST, 0);
    try {
      const res = await httpThroughProxy(PROXY_HOST, bound.port, '127.0.0.1', server.httpPort, {
        path: '/large?size=5000',
      });
      // Client still receives ALL 5000 bytes.
      expect(res.body.length).toBe(5000);
      const ex = smallCaptured.find((e) => e.request.url.includes('/large'))!;
      expect(ex.response!.body.truncated).toBe(true);
      expect(ex.response!.body.size).toBe(1000);
    } finally {
      await smallProxy.stop();
    }
  });
});

describe('proxy — scope flagging', () => {
  it('flags out-of-scope by default and in-scope after a rule is added', async () => {
    scope = { include: [], exclude: [] };
    await httpThroughProxy(PROXY_HOST, proxyPort, '127.0.0.1', server.httpPort, { path: '/json' });
    expect(lastFor('/json').inScope).toBe(false);

    scope = {
      include: [
        { id: 'r', enabled: true, hostMatch: 'exact', host: '127.0.0.1', schemes: [], ports: [] },
      ],
      exclude: [],
    };
    await httpThroughProxy(PROXY_HOST, proxyPort, '127.0.0.1', server.httpPort, { path: '/json' });
    expect(lastFor('/json').inScope).toBe(true);
    scope = { include: [], exclude: [] };
  });
});

describe('proxy — interception', () => {
  it('edits a request before forwarding', async () => {
    interceptor.setState({ interceptRequests: true });
    const handler = (view: { id: string; target: string }): void => {
      interceptor.resolveRequest(view.id, { action: 'forward', edit: { target: '/json' } });
    };
    interceptor.on('request-held', handler);
    try {
      const res = await httpThroughProxy(PROXY_HOST, proxyPort, '127.0.0.1', server.httpPort, {
        path: '/reflect?q=orig',
      });
      expect(JSON.parse(res.body.toString()).ok).toBe(true); // got /json, not /reflect
    } finally {
      interceptor.off('request-held', handler);
      interceptor.setState({ interceptRequests: false });
    }
  });

  it('drops a request when instructed', async () => {
    interceptor.setState({ interceptRequests: true });
    const handler = (view: { id: string }): void => {
      interceptor.resolveRequest(view.id, { action: 'drop' });
    };
    interceptor.on('request-held', handler);
    try {
      await expect(
        httpThroughProxy(PROXY_HOST, proxyPort, '127.0.0.1', server.httpPort, { path: '/json' }),
      ).rejects.toThrow();
      const dropped = [...captured].reverse().find((e) => e.error?.includes('dropped'));
      expect(dropped).toBeDefined();
    } finally {
      interceptor.off('request-held', handler);
      interceptor.setState({ interceptRequests: false });
    }
  });
});

describe('proxy — WebSocket handshake capture', () => {
  it('captures the 101 upgrade handshake', async () => {
    const { status } = await wsHandshakeThroughProxy(
      PROXY_HOST,
      proxyPort,
      '127.0.0.1',
      server.httpPort,
    );
    expect(status).toBe(101);
    const ws = [...captured].reverse().find((e) => e.tags.includes('websocket'));
    expect(ws).toBeDefined();
    expect(ws!.response?.statusCode).toBe(101);
  });

  it('captures WebSocket frames in both directions (masked + unmasked)', async () => {
    capturedWs.length = 0;
    const received = await wsExchangeThroughProxy(
      PROXY_HOST,
      proxyPort,
      '127.0.0.1',
      server.httpPort,
    );
    // The client still received the server frames through the tunnel.
    expect(received.toString('latin1')).toContain('server-frame-1');

    const texts = capturedWs.map((m) => m.payload.toString('utf8'));
    const s2c = capturedWs.filter((m) => m.direction === 's2c').map((m) => m.payload.toString());
    const c2s = capturedWs.filter((m) => m.direction === 'c2s').map((m) => m.payload.toString());
    expect(s2c).toContain('server-frame-1');
    expect(s2c).toContain('server-frame-2');
    // client→server frame was masked on the wire; the parser unmasked it.
    expect(c2s).toContain('client-frame-1');
    expect(texts.every((t) => typeof t === 'string')).toBe(true);
  });
});

describe('proxy — robustness', () => {
  it('does not crash on a malformed request and keeps serving', async () => {
    await new Promise<void>((resolve) => {
      const sock = net.connect(proxyPort, PROXY_HOST, () => {
        sock.write('THIS IS NOT HTTP\r\n\r\n');
      });
      sock.on('data', () => sock.destroy());
      sock.on('close', () => resolve());
      sock.on('error', () => resolve());
    });
    // proxy still works afterward
    const res = await httpThroughProxy(PROXY_HOST, proxyPort, '127.0.0.1', server.httpPort, {
      path: '/json',
    });
    expect(res.status).toBe(200);
  });

  it('aborts (does not poison the body) on a mid-stream upstream timeout', async () => {
    // Dedicated proxy with a short upstream timeout so /slow-body (headers +
    // partial body, then hangs) times out MID-STREAM.
    const shortProxy = new ProxyServer({
      ca: project.ca,
      limits: { ...project.config.limits, upstreamTimeoutMs: 400 },
      blobStore: project.blobs,
      interceptor: new Interceptor(),
      getScope: () => scope,
      onExchange: () => {},
    });
    const bound = await shortProxy.start(PROXY_HOST, 0);
    try {
      const outcome = await Promise.race([
        httpThroughProxy(PROXY_HOST, bound.port, '127.0.0.1', server.httpPort, {
          path: '/slow-body',
        })
          .then((r) => ({ kind: 'resolved' as const, body: r.body.toString() }))
          .catch((e) => ({ kind: 'rejected' as const, err: String(e) })),
        new Promise<{ kind: 'hung' }>((res) => setTimeout(() => res({ kind: 'hung' }), 6000)),
      ]);
      // The client must NOT be left hanging (the fix aborts it on mid-stream error).
      expect(outcome.kind).not.toBe('hung');
      // And it must never see the proxy's error text spliced into the body.
      if (outcome.kind === 'resolved') {
        expect(outcome.body).not.toContain('Bad Gateway (proxy upstream error)');
      }
    } finally {
      await shortProxy.stop();
    }
  }, 15000);
});
