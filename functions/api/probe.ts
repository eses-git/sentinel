/**
 * Cloudflare Pages Function — `GET /api/probe`
 *
 * A privacy-aware diagnostic endpoint that reflects everything a remote server
 * can learn about a visitor at the network layer. It never persists or
 * forwards data; the response is marked `Cache-Control: no-store`.
 *
 * The single endpoint performs three jobs:
 *
 *   1. **IP & Geo inspection** — reads the client IP (from the
 *      `CF-Connecting-IP` header) and country / city / region / ASN /
 *      organisation (from Cloudflare's `request.cf` object).
 *
 *   2. **Header audit** — summarises the client's identifying headers:
 *      `User-Agent`, `Accept-Language`, and every `Sec-Fetch-*` directive.
 *
 *   3. **Security header scan** — when a `?target=` URL is supplied, the
 *      function fetches that site and reports which of five critical security
 *      headers (`Content-Security-Policy`, `Strict-Transport-Security`,
 *      `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`) are
 *      missing from its response.
 *
 * ---------------------------------------------------------------------------
 * Type note: `@cloudflare/workers-types` is intentionally **not** a dependency
 * of this project (the `functions/` directory is excluded from the Vite build),
 * so the runtime shapes this file relies on are declared inline below.
 */

/** Geo/IP fields Cloudflare exposes on `request.cf`. */
interface RequestCfProperties {
  country?: string
  city?: string
  region?: string
  regionCode?: string
  continent?: string
  timezone?: string
  latitude?: string
  longitude?: string
  postalCode?: string
  asn?: number
  asOrganization?: string
  colo?: string
}

/** A standard `Request` augmented with Cloudflare's `cf` property. */
interface CfRequest extends Request {
  cf?: RequestCfProperties
}

/** Minimal Pages Function event context (only the pieces this handler uses). */
interface PagesFunctionContext {
  request: CfRequest
  env: Record<string, unknown>
}

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

/**
 * Collects the client's identifying headers into a plain object.
 *
 * @param request The incoming request.
 * @returns The `User-Agent`, `Accept-Language` and `Sec-Fetch-*` directives.
 */
function collectClientHeaders(request: Request) {
  // Sec-Fetch headers share the `sec-fetch-` prefix; gather the common set.
  const secFetch: Record<string, string> = {}
  for (const name of ['dest', 'mode', 'site', 'user']) {
    const value = request.headers.get(`sec-fetch-${name}`)
    if (value) secFetch[name] = value
  }

  return {
    userAgent: request.headers.get('user-agent'),
    acceptLanguage: request.headers.get('accept-language'),
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
 * @returns A JSON `Response`.
 */
function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store',
    },
  })
}

/**
 * Pages Function handler for `GET /api/probe`.
 *
 * Builds the client identity + geo + header summary, then optionally scans a
 * `?target=` URL's security headers.
 *
 * @param context The Pages Function event context.
 * @returns A JSON `Response`.
 */
export async function onRequestGet(
  context: PagesFunctionContext,
): Promise<Response> {
  const { request } = context

  // `request.cf` may be absent outside the Cloudflare edge (e.g. local tests).
  const cf = request.cf ?? {}

  // Extract the optional target URL from the query string.
  const target = new URL(request.url).searchParams.get('target')

  const result: ProbeResponse = {
    // Cloudflare injects the real client IP into this header at the edge.
    ip: request.headers.get('cf-connecting-ip'),
    geo: {
      country: cf.country ?? null,
      city: cf.city ?? null,
      region: cf.region ?? null,
      continent: cf.continent ?? null,
      timezone: cf.timezone ?? null,
      latitude: cf.latitude ?? null,
      longitude: cf.longitude ?? null,
    },
    asn: cf.asn ?? null,
    organization: cf.asOrganization ?? null,
    colo: cf.colo ?? null,
    clientHeaders: collectClientHeaders(request),
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

