import { useState } from 'react'
import type { ReactElement } from 'react'
import { useNetworkProbe } from '../hooks/useNetworkProbe'
import type { SecurityHeaderCheck } from '../hooks/useNetworkProbe'

/** Possible visual statuses for the network probe card. */
type Status = 'idle' | 'probing' | 'ready' | 'error'

/** Styling metadata for a status badge. */
interface StatusBadge {
  label: string
  className: string
  dot: string
}

/** Tailwind class maps for every possible status. */
const STATUS_BADGES: Record<Status, StatusBadge> = {
  idle: {
    label: 'IDLE',
    className:
      'border-slate-400 bg-slate-100 text-slate-600 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-300',
    dot: 'bg-slate-400',
  },
  probing: {
    label: 'PROBING',
    className:
      'border-amber-400 bg-amber-50 text-amber-700 dark:border-amber-500/60 dark:bg-amber-500/10 dark:text-amber-300',
    dot: 'bg-amber-500 animate-pulse',
  },
  ready: {
    label: 'READY',
    className:
      'border-emerald-400 bg-emerald-50 text-emerald-700 dark:border-emerald-500/60 dark:bg-emerald-500/10 dark:text-emerald-300',
    dot: 'bg-emerald-500',
  },
  error: {
    label: 'ERROR',
    className:
      'border-red-400 bg-red-50 text-red-700 dark:border-red-500/60 dark:bg-red-500/10 dark:text-red-300',
    dot: 'bg-red-500',
  },
}

/** The five security headers audited by the probe endpoint. */
const SECURITY_HEADERS = [
  'Content-Security-Policy',
  'Strict-Transport-Security',
  'X-Frame-Options',
  'X-Content-Type-Options',
  'Referrer-Policy',
] as const

/** Props for the small {@link Stat} label/value cell. */
interface StatProps {
  label: string
  value: string | number | null
}

/**
 * A square label/value cell used to render identity and geo fields.
 *
 * @param props See {@link StatProps}.
 * @returns The stat cell element.
 */
function Stat({ label, value }: StatProps): ReactElement {
  return (
    <div className="border border-slate-300 px-3 py-2 dark:border-slate-800">
      <p className="font-mono text-[10px] uppercase tracking-wider text-slate-400 dark:text-slate-500">
        {label}
      </p>
      <p className="mt-0.5 break-all font-mono text-sm text-slate-800 dark:text-slate-200">
        {value ?? '—'}
      </p>
    </div>
  )
}

/** Props for the {@link SectionTitle} sub-component. */
interface SectionTitleProps {
  /** Section heading text. */
  title: string
}

/**
 * A bordered section heading used to separate the card's result blocks.
 *
 * @param props See {@link SectionTitleProps}.
 * @returns The section heading element.
 */
function SectionTitle({ title }: SectionTitleProps): ReactElement {
  return (
    <div className="border-b border-slate-300 bg-slate-50 px-3 py-2 dark:border-slate-800 dark:bg-slate-950">
      <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-200">
        {title}
      </h3>
    </div>
  )
}

/** Props for the {@link SecurityHeaderRow} sub-component. */
interface SecurityHeaderRowProps {
  /** The security header name. */
  header: string
  /** The matching check result, or `undefined` when the target wasn't scanned. */
  check?: SecurityHeaderCheck
}

/**
 * Renders a single security header with a pass/fail (or unscanned) badge.
 *
 * @param props See {@link SecurityHeaderRowProps}.
 * @returns The security header row element.
 */
function SecurityHeaderRow({
  header,
  check,
}: SecurityHeaderRowProps): ReactElement {
  // `undefined` check → not scanned; otherwise present = pass, absent = missing.
  const state = !check ? 'unscanned' : check.present ? 'present' : 'missing'

  const badgeClass =
    state === 'present'
      ? 'border-emerald-400 bg-emerald-50 text-emerald-700 dark:border-emerald-500/60 dark:bg-emerald-500/10 dark:text-emerald-300'
      : state === 'missing'
        ? 'border-red-400 bg-red-50 text-red-700 dark:border-red-500/60 dark:bg-red-500/10 dark:text-red-300'
        : 'border-slate-400 bg-slate-100 text-slate-500 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-400'

  const badgeLabel =
    state === 'present' ? 'PRESENT' : state === 'missing' ? 'MISSING' : '—'

  return (
    <li className="flex items-center justify-between gap-3 px-3 py-2">
      <span className="font-mono text-xs text-slate-800 dark:text-slate-200">
        {header}
      </span>
      <span
        className={`inline-flex items-center gap-2 border px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider ${badgeClass}`}
      >
        {state !== 'unscanned' && (
          <span
            className={`h-1.5 w-1.5 ${
              state === 'present' ? 'bg-emerald-500' : 'bg-red-500'
            }`}
            aria-hidden="true"
          />
        )}
        {badgeLabel}
      </span>
    </li>
  )
}

/**
 * Main network probe diagnostic panel.
 *
 * Displays client ASN/ISP info, geo-location data, the client's identifying
 * headers, and a security-header audit for a user-supplied target URL, with a
 * sharp "RUN NETWORK & HEADER PROBE" action button.
 *
 * @returns The network probe card element.
 */
export function NetworkProbeCard(): ReactElement {
  const { probeData, isLoading, error, runProbe } = useNetworkProbe()
  const [target, setTarget] = useState('')

  const status: Status = isLoading
    ? 'probing'
    : error
      ? 'error'
      : probeData
        ? 'ready'
        : 'idle'
  const badge = STATUS_BADGES[status]

  // Run the probe, passing the target URL only when it is non-empty.
  const handleRun = () => {
    runProbe(target.trim() || undefined)
  }

  return (
    <section className="border border-slate-300 bg-white dark:border-slate-800 dark:bg-slate-900">
      {/* Card header: title + status badge */}
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-300 px-5 py-4 dark:border-slate-800">
        <div>
          <h2 className="font-mono text-base font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Network &amp; Security Header Probe
          </h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Reveals the network identity a remote server sees, and audits a
            target site&apos;s security headers.
          </p>
        </div>
        <span
          className={`inline-flex items-center gap-2 border px-3 py-1 font-mono text-xs font-bold uppercase tracking-wider ${badge.className}`}
        >
          <span className={`h-2 w-2 ${badge.dot}`} aria-hidden="true" />
          {badge.label}
        </span>
      </header>

      {/* Card body */}
      <div className="px-5 py-5">
        {/* Action row: target input + run button */}
        <div className="flex flex-wrap items-center gap-3">
          <input
            type="url"
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="https://example.com (optional target)"
            aria-label="Target URL to scan security headers"
            className="min-w-0 flex-1 border border-slate-300 bg-white px-3 py-2 font-mono text-xs text-slate-800 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-500 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-200 dark:placeholder:text-slate-500"
          />
          <button
            type="button"
            onClick={handleRun}
            disabled={isLoading}
            className="border border-slate-900 bg-slate-900 px-4 py-2 font-mono text-xs font-bold uppercase tracking-wider text-white transition-colors hover:bg-slate-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 disabled:cursor-not-allowed disabled:opacity-60 dark:border-slate-100 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300"
          >
            {isLoading ? 'Probing…' : 'Run Network & Header Probe'}
          </button>
        </div>

        {/* Error banner */}
        {error && (
          <div className="mt-4 border border-red-300 bg-red-50 px-4 py-3 font-mono text-xs text-red-700 dark:border-red-500/50 dark:bg-red-500/10 dark:text-red-300">
            <span className="font-bold">ERROR:</span> {error}
          </div>
        )}

        {/* Results */}
        {probeData && (
          <div className="mt-6 space-y-4">
            {/* Identity + geo grid */}
            <div className="grid gap-4 md:grid-cols-2">
              <div className="border border-slate-300 dark:border-slate-800">
                <SectionTitle title="Client Identity" />
                <div className="grid grid-cols-2 gap-px bg-slate-200 dark:bg-slate-800">
                  <Stat label="IP Address" value={probeData.ip} />
                  <Stat label="ASN" value={probeData.asn} />
                  <Stat label="ISP / Org" value={probeData.organization} />
                  <Stat label="Edge Colo" value={probeData.colo} />
                </div>
              </div>

              <div className="border border-slate-300 dark:border-slate-800">
                <SectionTitle title="Geo-Location" />
                <div className="grid grid-cols-2 gap-px bg-slate-200 dark:bg-slate-800">
                  <Stat label="Country" value={probeData.geo.country} />
                  <Stat label="City" value={probeData.geo.city} />
                  <Stat label="Region" value={probeData.geo.region} />
                  <Stat label="Continent" value={probeData.geo.continent} />
                  <Stat label="Timezone" value={probeData.geo.timezone} />
                  <Stat
                    label="Coordinates"
                    value={
                      probeData.geo.latitude && probeData.geo.longitude
                        ? `${probeData.geo.latitude}, ${probeData.geo.longitude}`
                        : null
                    }
                  />
                </div>
              </div>
            </div>

            {/* Client headers */}
            <div className="border border-slate-300 dark:border-slate-800">
              <SectionTitle title="Client Headers (as seen by the edge)" />
              <ul className="divide-y divide-slate-200 dark:divide-slate-800">
                <li className="flex items-center justify-between gap-3 px-3 py-2">
                  <span className="font-mono text-xs text-slate-400 dark:text-slate-500">
                    User-Agent
                  </span>
                  <span className="break-all text-right font-mono text-xs text-slate-800 dark:text-slate-200">
                    {probeData.clientHeaders.userAgent ?? '—'}
                  </span>
                </li>
                <li className="flex items-center justify-between gap-3 px-3 py-2">
                  <span className="font-mono text-xs text-slate-400 dark:text-slate-500">
                    Accept-Language
                  </span>
                  <span className="break-all text-right font-mono text-xs text-slate-800 dark:text-slate-200">
                    {probeData.clientHeaders.acceptLanguage ?? '—'}
                  </span>
                </li>
                {Object.entries(probeData.clientHeaders.secFetch).map(
                  ([name, value]) => (
                    <li
                      key={name}
                      className="flex items-center justify-between gap-3 px-3 py-2"
                    >
                      <span className="font-mono text-xs text-slate-400 dark:text-slate-500">
                        Sec-Fetch-{name}
                      </span>
                      <span className="font-mono text-xs text-slate-800 dark:text-slate-200">
                        {value}
                      </span>
                    </li>
                  ),
                )}
              </ul>
            </div>

            {/* Security header audit */}
            <div className="border border-slate-300 dark:border-slate-800">
              <SectionTitle title="Security Header Audit" />
              {probeData.scannedTarget && (
                <p className="border-b border-slate-200 px-3 py-2 font-mono text-[11px] text-slate-500 dark:border-slate-800 dark:text-slate-400">
                  Target: {probeData.scannedTarget}
                </p>
              )}
              <ul className="divide-y divide-slate-200 dark:divide-slate-800">
                {SECURITY_HEADERS.map((header) => (
                  <SecurityHeaderRow
                    key={header}
                    header={header}
                    check={probeData.securityHeaders?.find(
                      (check) => check.header === header,
                    )}
                  />
                ))}
              </ul>
              {probeData.targetError && (
                <p className="border-t border-red-300 bg-red-50 px-3 py-2 font-mono text-[11px] text-red-700 dark:border-red-500/50 dark:bg-red-500/10 dark:text-red-300">
                  Target scan error: {probeData.targetError}
                </p>
              )}
            </div>

          </div>
        )}
      </div>

      {/* Card footer */}
      <footer className="border-t border-slate-300 px-5 py-3 dark:border-slate-800">
        <p className="font-mono text-[11px] text-slate-400 dark:text-slate-500">
          Powered by a Cloudflare Pages Function at <code>/api/probe</code>.
        </p>
      </footer>
    </section>
  )
}


