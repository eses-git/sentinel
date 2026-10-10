import { useState } from 'react'
import type { ReactElement } from 'react'
import { useWebRTCLeaks } from '../hooks/useWebRTCLeaks'

/**
 * Overall security verdict derived from the scan results.
 * (A string union is used instead of an `enum` for `erasableSyntaxOnly`.)
 */
type Verdict = 'idle' | 'scanning' | 'error' | 'secure' | 'leak' | 'local-only'

/** Styling metadata for a single verdict badge. */
interface VerdictBadge {
  /** Human-readable badge text. */
  label: string
  /** Tailwind classes for the badge border/background/text. */
  className: string
  /** Tailwind class for the status "dot" indicator. */
  dot: string
}

/** Tailwind class maps for every possible verdict. */
const VERDICT_BADGES: Record<Verdict, VerdictBadge> = {
  idle: {
    label: 'IDLE',
    className:
      'border-slate-400 bg-slate-100 text-slate-600 dark:border-slate-600 dark:bg-slate-900 dark:text-slate-300',
    dot: 'bg-slate-400',
  },
  scanning: {
    label: 'SCANNING',
    className:
      'border-amber-400 bg-amber-50 text-amber-700 dark:border-amber-500/60 dark:bg-amber-500/10 dark:text-amber-300',
    dot: 'bg-amber-500 animate-pulse',
  },
  error: {
    label: 'ERROR',
    className:
      'border-red-400 bg-red-50 text-red-700 dark:border-red-500/60 dark:bg-red-500/10 dark:text-red-300',
    dot: 'bg-red-500',
  },
  secure: {
    label: 'SECURE',
    className:
      'border-emerald-400 bg-emerald-50 text-emerald-700 dark:border-emerald-500/60 dark:bg-emerald-500/10 dark:text-emerald-300',
    dot: 'bg-emerald-500',
  },
  'local-only': {
    label: 'LOCAL ONLY',
    className:
      'border-amber-400 bg-amber-50 text-amber-700 dark:border-amber-500/60 dark:bg-amber-500/10 dark:text-amber-300',
    dot: 'bg-amber-500',
  },
  leak: {
    label: 'LEAK DETECTED',
    className:
      'border-red-500 bg-red-50 text-red-700 dark:border-red-500/60 dark:bg-red-500/10 dark:text-red-300',
    dot: 'bg-red-500',
  },
}

/**
 * Computes the overall verdict from the current scan state.
 *
 * Priority order: scanning > error > idle > leak > local-only > secure.
 *
 * @param isGathering Whether a scan is in progress.
 * @param error        Any error message (or `null`).
 * @param hasScanned   Whether the user has run a scan at least once.
 * @param publicIps    Discovered public IPs.
 * @param mdnsHosts    Discovered mDNS hostnames.
 * @param localIps     Discovered local IPs.
 * @returns The resolved {@link Verdict}.
 */
function computeVerdict(
  isGathering: boolean,
  error: string | null,
  hasScanned: boolean,
  publicIps: string[],
  mdnsHosts: string[],
  localIps: string[],
): Verdict {
  if (isGathering) return 'scanning'
  if (error) return 'error'
  if (!hasScanned) return 'idle'
  if (publicIps.length > 0 || mdnsHosts.length > 0) return 'leak'
  if (localIps.length > 0) return 'local-only'
  return 'secure'
}

/**
 * Threat-level styling for an address table badge.
 */
type Severity = 'danger' | 'warning' | 'info'

/** Tailwind class map for table badge severities. */
const SEVERITY_BADGES: Record<Severity, string> = {
  danger:
    'border-red-400 bg-red-50 text-red-700 dark:border-red-500/60 dark:bg-red-500/10 dark:text-red-300',
  warning:
    'border-amber-400 bg-amber-50 text-amber-700 dark:border-amber-500/60 dark:bg-amber-500/10 dark:text-amber-300',
  info: 'border-sky-400 bg-sky-50 text-sky-700 dark:border-sky-500/60 dark:bg-sky-500/10 dark:text-sky-300',
}

/** Props accepted by the {@link IpTable} sub-component. */
interface IpTableProps {
  /** Table heading text. */
  title: string
  /** Threat-level badge label. */
  badgeLabel: string
  /** Threat severity (drives the badge colour). */
  severity: Severity
  /** Detected addresses to list. */
  addresses: string[]
  /** Message shown when `addresses` is empty. */
  emptyText: string
}

/**
 * Renders a single "detected addresses" table with a title, a severity badge,
 * and a list of addresses (or an empty-state message).
 *
 * @param props See {@link IpTableProps}.
 * @returns The table element.
 */
function IpTable({
  title,
  badgeLabel,
  severity,
  addresses,
  emptyText,
}: IpTableProps): ReactElement {
  return (
    <div className="flex flex-col border border-slate-300 dark:border-slate-800">
      {/* Table header */}
      <div className="flex items-center justify-between gap-2 border-b border-slate-300 bg-slate-50 px-3 py-2 dark:border-slate-800 dark:bg-slate-950">
        <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-200">
          {title}
        </h3>
        <span
          className={`border px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider ${SEVERITY_BADGES[severity]}`}
        >
          {badgeLabel}
        </span>
      </div>

      {/* Table body */}
      <ul className="divide-y divide-slate-200 dark:divide-slate-800">
        {addresses.length === 0 ? (
          <li className="px-3 py-3 font-mono text-xs text-slate-400 dark:text-slate-500">
            {emptyText}
          </li>
        ) : (
          addresses.map((address) => (
            <li
              key={address}
              className="flex items-center justify-between px-3 py-2 font-mono text-xs text-slate-800 dark:text-slate-200"
            >
              <span className="break-all">{address}</span>
              <span
                className="ml-2 h-1.5 w-1.5 shrink-0 bg-slate-300 dark:bg-slate-600"
                aria-hidden="true"
              />
            </li>
          ))
        )}
      </ul>
    </div>
  )
}

/**
 * Main WebRTC diagnostic panel.
 *
 * Presents the WebRTC leak status with sharp action buttons, a verdict badge,
 * warning banners, and three detected-address tables (public IPs, local IPs
 * and mDNS hostnames).
 *
 * @returns The WebRTC audit card element.
 */
export function WebRTCAuditCard(): ReactElement {
  const { localIps, publicIps, mdnsHosts, isGathering, error, startScan } =
    useWebRTCLeaks()

  // Track whether the user has run a scan (the hook itself doesn't expose it).
  const [hasScanned, setHasScanned] = useState(false)

  const verdict = computeVerdict(
    isGathering,
    error,
    hasScanned,
    publicIps,
    mdnsHosts,
    localIps,
  )
  const badge = VERDICT_BADGES[verdict]

  // Start the scan and mark that a scan has been initiated.
  const handleScan = () => {
    setHasScanned(true)
    startScan()
  }

  return (
    <section className="border border-slate-300 bg-white dark:border-slate-800 dark:bg-slate-900">
      {/* Card header: title + verdict badge */}
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-300 px-5 py-4 dark:border-slate-800">
        <div>
          <h2 className="font-mono text-base font-bold tracking-tight text-slate-900 dark:text-slate-100">
            WebRTC IP Leak Audit
          </h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Detects whether your real public or local IP addresses leak through
            the WebRTC API.
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
        {/* Action row */}
        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={handleScan}
            disabled={isGathering}
            className="border border-slate-900 bg-slate-900 px-4 py-2 font-mono text-xs font-bold uppercase tracking-wider text-white transition-colors hover:bg-slate-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 disabled:cursor-not-allowed disabled:opacity-60 dark:border-slate-100 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300"
          >
            {isGathering ? 'Scanning…' : hasScanned ? 'Re-scan' : 'Start Scan'}
          </button>
          <p className="font-mono text-xs text-slate-500 dark:text-slate-400">
            {isGathering
              ? 'Gathering ICE candidates…'
              : 'Uses public STUN servers to enumerate network interfaces.'}
          </p>
        </div>

        {/* Error banner */}
        {error && (
          <div className="mt-4 border border-red-300 bg-red-50 px-4 py-3 font-mono text-xs text-red-700 dark:border-red-500/50 dark:bg-red-500/10 dark:text-red-300">
            <span className="font-bold">ERROR:</span> {error}
          </div>
        )}

        {/* Detected-address tables */}
        <div className="mt-6 grid gap-4 md:grid-cols-3">
          <IpTable
            title="Public IPs"
            badgeLabel="Leak"
            severity="danger"
            addresses={publicIps}
            emptyText="No public IP detected."
          />
          <IpTable
            title="Local IPs"
            badgeLabel="LAN"
            severity="warning"
            addresses={localIps}
            emptyText="No local IP detected."
          />
          <IpTable
            title="mDNS Hosts"
            badgeLabel="Masked"
            severity="info"
            addresses={mdnsHosts}
            emptyText="No mDNS hostname detected."
          />
        </div>

        {/* Leak warning banner */}
        {verdict === 'leak' && (
          <div className="mt-4 border border-red-400 bg-red-50 px-4 py-3 font-mono text-xs text-red-700 dark:border-red-500/50 dark:bg-red-500/10 dark:text-red-300">
            <span className="font-bold">WARNING:</span> Your real IP address is
            exposed to WebRTC peers. If you rely on a VPN or proxy, disable
            WebRTC or use a browser extension to block it.
          </div>
        )}
      </div>

      {/* Card footer */}
      <footer className="border-t border-slate-300 px-5 py-3 dark:border-slate-800">
        <p className="font-mono text-[11px] text-slate-400 dark:text-slate-500">
          STUN: stun.l.google.com:19302 · stun.cloudflare.com:3478 — results are
          computed entirely in your browser.
        </p>
      </footer>
    </section>
  )
}


