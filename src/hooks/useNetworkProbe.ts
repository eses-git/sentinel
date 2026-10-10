import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Geo-location summary returned by the `/api/probe` endpoint.
 */
export interface GeoInfo {
  country: string | null
  city: string | null
  region: string | null
  continent: string | null
  timezone: string | null
  latitude: string | null
  longitude: string | null
}

/** A single security-header check result for a scanned target. */
export interface SecurityHeaderCheck {
  /** The header name (e.g. `Content-Security-Policy`). */
  header: string
  /** `true` when the target sent the header. */
  present: boolean
  /** The header value, or `null` when absent. */
  value: string | null
}

/** The client's identifying headers, as captured by the edge. */
export interface ClientHeaderAudit {
  userAgent: string | null
  acceptLanguage: string | null
  secFetch: Record<string, string>
}

/**
 * The full payload returned by the network probe endpoint.
 */
export interface ProbeResult {
  /** The client's public IP address (from `CF-Connecting-IP`). */
  ip: string | null
  /** Geo-location data derived from Cloudflare's `request.cf`. */
  geo: GeoInfo
  /** The client's Autonomous System Number (ASN). */
  asn: number | null
  /** The ISP / organisation owning the ASN. */
  organization: string | null
  /** The Cloudflare data-centre (colo) that served the request. */
  colo: string | null
  /** Summary of the client's identifying headers. */
  clientHeaders: ClientHeaderAudit
  /** Security-header checks for a scanned target, or `null` when unscanned. */
  securityHeaders: SecurityHeaderCheck[] | null
  /** The target URL that was scanned, or `null`. */
  scannedTarget: string | null
  /** An error produced while scanning the target, or `null`. */
  targetError: string | null
}

/**
 * State and actions returned by the `useNetworkProbe` hook.
 */
export interface NetworkProbeState {
  /** The latest probe payload, or `null` before the first successful run. */
  probeData: ProbeResult | null
  /** `true` while a probe request is in flight. */
  isLoading: boolean
  /** Human-readable error message, or `null`. */
  error: string | null
  /** Triggers a fresh probe; optionally scan a target's security headers. */
  runProbe: (targetUrl?: string) => void
}

/**
 * The relative path of the Cloudflare Pages Function. Served same-origin in
 * production; unavailable under the plain Vite dev server (see README).
 */
const PROBE_ENDPOINT = '/api/probe'

/**
 * Custom React hook that fetches network telemetry from the `/api/probe`
 * Pages Function (IP, geo, ASN, client headers, and optional target security
 * header scan).
 *
 * @returns {@link NetworkProbeState} with the probe payload, loading/error
 *          state and a `runProbe` trigger.
 */
export function useNetworkProbe(): NetworkProbeState {
  const [probeData, setProbeData] = useState<ProbeResult | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Guards setState after unmount (re-armed on mount for StrictMode).
  const mountedRef = useRef(false)
  // Monotonic run id so only the latest run may write results.
  const runIdRef = useRef(0)

  const runProbe = useCallback((targetUrl?: string) => {
    const runId = ++runIdRef.current

    // Reset state for a fresh run.
    setProbeData(null)
    setError(null)
    setIsLoading(true)

    void (async () => {
      try {
        // Append the target as a query parameter when a scan is requested.
        const url = targetUrl
          ? `${PROBE_ENDPOINT}?target=${encodeURIComponent(targetUrl)}`
          : PROBE_ENDPOINT

        const response = await fetch(url, {
          method: 'GET',
          headers: { Accept: 'application/json' },
        })

        if (!response.ok) {
          // A 404 means the Pages Function isn't available — typical under the
          // plain Vite dev server. Surface an actionable hint.
          const detail =
            response.status === 404
              ? 'Probe endpoint not found. Run `wrangler pages dev` to serve Pages Functions locally, or deploy to Cloudflare Pages.'
              : `Probe request failed (HTTP ${response.status}).`
          throw new Error(detail)
        }

        const data = (await response.json()) as ProbeResult

        // Discard stale results (a newer run supersedes this one).
        if (runId !== runIdRef.current) return
        if (!mountedRef.current) return

        setProbeData(data)
      } catch (err) {
        if (runId !== runIdRef.current) return
        if (!mountedRef.current) return
        setError(
          err instanceof Error ? err.message : 'Network probe failed.',
        )
      } finally {
        if (runId === runIdRef.current && mountedRef.current) {
          setIsLoading(false)
        }
      }
    })()
  }, [])

  // Re-arm the mounted flag on mount; mark unmounted in cleanup.
  useEffect(() => {
    mountedRef.current = true
    return () => {
      mountedRef.current = false
    }
  }, [])

  return { probeData, isLoading, error, runProbe }
}
