/// <reference types="@cloudflare/workers-types" />

/**
 * Cloudflare Pages Function — `/api/probe`
 *
 * A privacy-aware diagnostic endpoint that reflects the network identity a
 * remote server can observe about a visitor. It never persists or forwards
 * data, and every response carries `Cache-Control: no-store`.
 *
 * Responsibilities:
 *
 *   1. **IP & Geo inspection** — client IP (from `CF-Connecting-IP`), ASN,
 *      organisation, country, city, region, continent, timezone and
 *      coordinates (from Cloudflare's `request.cf`).
 *
 *   2. **Header audit** — `User-Agent`, `Accept-Language`, and the `Sec-Fetch-*`
 *      directives sent by the client.
 *
 *   3. **Security header scan** — when a `?target=` query parameter (GET) or a
 *      `{ "target": "..." }` JSON body (POST) is supplied, the function fetches
 *      that site and reports whether five critical security headers are
 *      present or missing.
 *
 * The `onRequest` handler responds to **all** HTTP methods (including CORS
 * `OPTIONS` preflight), which is why it is used instead of `onRequestGet`.
 */

/**
 * Environment bindings type. Empty for now — add KV namespaces, D1 databases
 * or other bindings here as they are configured.
 */
type Env = Record<string, unknown>

/** Geo-location summary returned to the client. */
interface GeoInfo {
  country: string | null
  city: string | null
  region: string | null
  continent: string | null
  timezone: string | null
  latitude: string | null
  longitude: string | null
}

/** A single security-header check result. */
interface SecurityHeaderCheck {
  header: string
  present: boolean
  value: string | null
}

/** The JSON shape returned by this endpoint. */
interface ProbeResponse {
  ip: string | null
  geo: GeoInfo
  asn: number | null
  organization: string | null
  colo: string | null
  clientHeaders: {
    userAgent: string | null
    acceptLanguage: string | null
    secFetch: Record<string, string>
  }
  securityHeaders: SecurityHeaderCheck[] | null
  scannedTarget: string | null
  targetError: string | null
}

/** The five security headers this scanner audits. */
const SECURITY_HEADERS = [
  'Content-Security-Policy',
  'Strict-Transport-Security',
  'X-Frame-Options',
  'X-Content-Type-Options',
  'Referrer-Policy',
] as const

/** Shared CORS headers applied to every response. */
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
} as const

/**
 * Collects the client's identifying headers into a plain object.
 *
 * @param headers The incoming request headers.
 * @returns The `User-Agent`, `Accept-Language` and `Sec-Fetch-*` directives.
 */
function collectClientHeaders(headers: Headers) {
  // Sec-Fetch headers share the `sec-fetch-` prefix; gather the common set.
  const secFetch: Record<string, string> = {}
  for (const name of ['dest', 'mode', 'site', 'user']) {
    const value = headers.get(`sec-fetch-${name}`)
    if (value) secFetch[name] = value
  }

  return {
    userAgent: headers.get('user-agent'),
    acceptLanguage: headers.get('accept-language'),
    secFetch,
  }
}

/**
 * Fetches a target URL and audits its response for the five security headers.
 *
 * @param target The absolute http(s) URL to scan.
 * @returns An array of {@link SecurityHeaderCheck} results.
 */
async function scanTargetSecurityHeaders(
  target: string,
): Promise<SecurityHeaderCheck[]> {
  // Validate the protocol to avoid scanning non-http(s) schemes.
  const url = new URL(target)
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error('Only http:// and https:// targets are supported.')
  }

  const response = await fetch(url.toString(), {
    method: 'GET',
    redirect: 'follow',
  })

  // Map each known security header to its presence/value in the response.
  return SECURITY_HEADERS.map((header) => ({
    header,
    present: response.headers.has(header),
    value: response.headers.get(header),
  }))
}

/**
 * Serialises a value as JSON with CORS + no-store headers.
 *
 * @param data   The payload to serialise.
 * @param status The HTTP status code (defaults to 200).
 * @returns A JSON `Response` with `Content-Type: application/json`.
 */
function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...CORS_HEADERS,
      'Cache-Control': 'no-store',
    },
  })
}

/**
 * Pages Function handler for `/api/probe` (all HTTP methods).
 *
 * Builds the client identity + geo + header summary, then optionally scans a
 * target site's security headers. The target may arrive via `?target=` (GET)
 * or a `{ "target": "..." }` JSON body (POST).
 *
 * @param context The Pages Function event context.
 * @returns A JSON `Response`.
 */
export const onRequest: PagesFunction<Env> = async (context) => {
  const { request } = context

  // Answer CORS preflight (OPTIONS) requests immediately.
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: { ...CORS_HEADERS } })
  }

  // `request.cf` is populated at the Cloudflare edge and may be absent when the
  // function is run outside of Cloudflare (e.g. unit tests).
  const cf = request.cf

  // Resolve the target URL from the query string (GET) or the JSON body (POST).
  let target = new URL(request.url).searchParams.get('target')
  if (!target && request.method === 'POST') {
    try {
      const body = (await request.json()) as { target?: string }
      target = body.target ?? null
    } catch {
      target = null // Non-JSON or empty body — fall through.
    }
  }

  const result: ProbeResponse = {
    // Cloudflare injects the real client IP into `CF-Connecting-IP`.
    ip:
      request.headers.get('cf-connecting-ip') ??
      request.headers.get('x-forwarded-for'),
    geo: {
      country: cf?.country ?? null,
      city: cf?.city ?? null,
      region: cf?.region ?? null,
      continent: cf?.continent ?? null,
      timezone: cf?.timezone ?? null,
      latitude: cf?.latitude ?? null,
      longitude: cf?.longitude ?? null,
    },
    asn: cf?.asn ?? null,
    organization: cf?.asOrganization ?? null,
    colo: cf?.colo ?? null,
    clientHeaders: collectClientHeaders(request.headers),
    securityHeaders: null,
    scannedTarget: null,
    targetError: null,
  }

  // Optionally scan a target site's security headers. Failures are reported
  // inline (HTTP 200) rather than as a hard error, so the client still
  // receives its own identity/geo data.
  if (target) {
    result.scannedTarget = target
    try {
      result.securityHeaders = await scanTargetSecurityHeaders(target)
    } catch (err) {
      result.targetError =
        err instanceof Error ? err.message : 'Target scan failed.'
    }
  }

  return json(result)
}

