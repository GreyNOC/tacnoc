/**
 * Engagement identity applied to outbound bytes.
 *
 * Programs that ask researchers to identify their traffic mean *every* request,
 * not just the first one. So this is applied in the engine, on the two paths
 * that generate traffic (Repeater and the Variation engine), rather than left
 * to whoever typed the raw request — including the AI mesh, which types most of
 * them.
 *
 * Header order, casing, and duplicates are load-bearing everywhere else in this
 * codebase (see `shared/model.ts`), so the rewrite is deliberately minimal: an
 * existing header is replaced **in place**, keeping its position; later
 * duplicates of the same name are dropped so the target sees exactly one; a
 * missing header is appended. Nothing else is touched.
 *
 * Validation runs again here even though `setEngagementProfile` already refuses
 * an invalid profile — a project file can be hand-edited or imported from
 * elsewhere, and a CR/LF in a header value at this point is header injection
 * against a third party's production system. Invalid entries are dropped, never
 * sanitized into something the operator did not write.
 */

import type { HttpHeader } from '../../shared/model.js';
import type { EngagementProfile, IdentityHeader } from '../../shared/engagement.js';
import {
  MAX_IDENTITY_HEADERS,
  validateHeaderName,
  validateHeaderValue,
} from '../../shared/engagement.js';

/**
 * The headers this profile requires on generated traffic, invalid entries
 * removed. Empty when the profile mandates nothing.
 */
export function requiredIdentityHeaders(profile: EngagementProfile | undefined): IdentityHeader[] {
  if (!profile) return [];
  const out: IdentityHeader[] = [];
  const ua = profile.userAgent?.required ?? '';
  if (ua.trim() && !validateHeaderValue('User-Agent', ua)) {
    out.push({ name: 'User-Agent', value: ua });
  }
  const seen = new Set<string>(['user-agent']);
  for (const header of profile.identityHeaders ?? []) {
    const name = header?.name ?? '';
    const value = header?.value ?? '';
    if (validateHeaderName(name) || validateHeaderValue(name, value)) continue;
    const lower = name.toLowerCase();
    if (seen.has(lower)) continue;
    seen.add(lower);
    out.push({ name, value });
    // The count cap is enforced here too, not only in the setter. An imported
    // or hand-edited profile carrying hundreds of headers would otherwise put
    // half a megabyte of them on every request to a third party's production
    // system — the setter's validation is not the only way a profile arrives.
    if (out.length >= MAX_IDENTITY_HEADERS) break;
  }
  return out;
}

/** True when this profile should rewrite generated traffic at all. */
export function identityEnforced(profile: EngagementProfile | undefined): boolean {
  return !!profile?.userAgent?.enforce && requiredIdentityHeaders(profile).length > 0;
}

/**
 * Apply engagement identity to a request's headers. Returns the original array
 * unchanged when enforcement is off or nothing is required, so the common path
 * costs nothing.
 */
export function applyIdentity(
  headers: readonly HttpHeader[],
  profile: EngagementProfile | undefined,
): HttpHeader[] {
  if (!identityEnforced(profile)) return [...headers];
  const required = requiredIdentityHeaders(profile);
  const byLower = new Map(required.map((h) => [h.name.toLowerCase(), h]));
  const applied = new Set<string>();

  const out: HttpHeader[] = [];
  for (const header of headers) {
    const lower = header.name.toLowerCase();
    const replacement = byLower.get(lower);
    if (!replacement) {
      out.push(header);
      continue;
    }
    // Replace the first occurrence in place; drop any later duplicate so the
    // target receives exactly one copy of an identifying header.
    if (!applied.has(lower)) {
      applied.add(lower);
      out.push({ name: replacement.name, value: replacement.value });
    }
  }
  for (const header of required) {
    if (!applied.has(header.name.toLowerCase())) out.push({ ...header });
  }
  return out;
}

export interface IdentityCheck {
  /** True when every required header is present with the exact required value. */
  compliant: boolean;
  /** Required headers that are absent or carry the wrong value. */
  missing: string[];
  /** The User-Agent actually present, for reporting what the target would see. */
  userAgent?: string;
}

/**
 * Check headers against the profile without changing them. Used to report
 * compliance for traffic that was already sent (including traffic captured
 * through the proxy, which is never rewritten).
 */
export function checkIdentity(
  headers: readonly HttpHeader[],
  profile: EngagementProfile | undefined,
): IdentityCheck {
  const required = requiredIdentityHeaders(profile);
  const observedUa = headers.find((h) => h.name.toLowerCase() === 'user-agent')?.value;
  const missing: string[] = [];
  for (const want of required) {
    const lower = want.name.toLowerCase();
    const got = headers.filter((h) => h.name.toLowerCase() === lower);
    if (got.length !== 1 || got[0]!.value !== want.value) missing.push(want.name);
  }
  return {
    compliant: missing.length === 0,
    missing,
    ...(observedUa !== undefined ? { userAgent: observedUa } : {}),
  };
}
