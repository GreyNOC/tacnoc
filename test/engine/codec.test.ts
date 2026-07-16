import { describe, it, expect } from 'vitest';
import {
  urlEncode,
  urlDecode,
  base64Encode,
  base64Decode,
  hexEncode,
  hexDecode,
  htmlEncode,
  htmlDecode,
  gzipToBase64,
  gunzipFromBase64,
  hash,
  epochToIso,
  isoToEpochMs,
  inspectJwt,
  applyTransform,
} from '../../src/engine/transforms/codec.js';

describe('codec transforms', () => {
  it('url encode/decode round-trips', () => {
    const s = 'a b&c=d/e?f#g';
    expect(urlDecode(urlEncode(s))).toBe(s);
  });

  it('base64 encode/decode round-trips', () => {
    expect(base64Decode(base64Encode('hello world'))).toBe('hello world');
  });

  it('hex encode/decode round-trips and rejects bad hex', () => {
    expect(hexDecode(hexEncode('GreyNOC'))).toBe('GreyNOC');
    expect(() => hexDecode('zz')).toThrow();
    expect(() => hexDecode('abc')).toThrow();
  });

  it('html entity encode/decode', () => {
    expect(htmlEncode('<a href="x">&\'')).toBe('&lt;a href=&quot;x&quot;&gt;&amp;&#39;');
    expect(htmlDecode('&lt;b&gt;&amp;&#39;&#x41;')).toBe("<b>&'A");
  });

  it('gzip round-trips through base64', () => {
    const s = 'compress me '.repeat(20);
    expect(gunzipFromBase64(gzipToBase64(s))).toBe(s);
  });

  it('hashes match known vectors', () => {
    expect(hash('sha256', 'abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
    expect(hash('md5', 'abc')).toBe('900150983cd24fb0d6963f7d28e17f72');
  });

  it('timestamp conversions round-trip', () => {
    const iso = epochToIso('1600000000');
    expect(iso).toBe('2020-09-13T12:26:40.000Z');
    expect(isoToEpochMs(iso)).toBe('1600000000000');
  });

  it('inspects a JWT without verifying or altering the signature', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJuYW1lIjoiQSJ9.abc123sig';
    const info = inspectJwt(jwt);
    expect((info.header as { alg: string }).alg).toBe('HS256');
    expect((info.payload as { sub: string }).sub).toBe('123');
    expect(info.signatureB64Url).toBe('abc123sig');
    expect(info.wellFormed).toBe(true);
    // The inspector never returns a re-signed or alg-stripped token.
    expect(info.note).toMatch(/not verified/i);
  });

  it('applyTransform dispatches by id and errors on unknown', () => {
    expect(applyTransform('base64.encode', 'x')).toBe(base64Encode('x'));
    expect(() => applyTransform('nope', 'x')).toThrow();
  });
});
