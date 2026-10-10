import { useEffect, useRef, useState } from 'react'
import type { ReactElement } from 'react'
import { useFingerprint } from '../hooks/useFingerprint'

/** Possible visual statuses for the fingerprint card. */
type Status = 'idle' | 'calculating' | 'ready' | 'error'

/** Styling metadata for a status badge. */
interface StatusBadge {
  /** Human-readable badge text. */
  label: string
  /** Tailwind classes for the badge border/background/text. */
  className: string
  /** Tailwind class for the status "dot" indicator. */
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
  calculating: {
    label: 'CALCULATING',
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

/**
 * Classifies an entropy score into a human-readable uniqueness label.
 *
 * @param score The estimated entropy in bits.
 * @returns A `{ label, className }` pair for the score badge.
 */
function entropyLabel(score: number): { label: string; className: string } {
  if (score >= 40) {
    return {
      label: 'VERY HIGH',
      className:
        'border-red-400 bg-red-50 text-red-700 dark:border-red-500/60 dark:bg-red-500/10 dark:text-red-300',
    }
  }
  if (score >= 30) {
    return {
      label: 'HIGH',
      className:
        'border-orange-400 bg-orange-50 text-orange-700 dark:border-orange-500/60 dark:bg-orange-500/10 dark:text-orange-300',
    }
  }
  if (score >= 20) {
    return {
      label: 'MODERATE',
      className:
        'border-amber-400 bg-amber-50 text-amber-700 dark:border-amber-500/60 dark:bg-amber-500/10 dark:text-amber-300',
    }
  }
  return {
    label: 'LOW',
    className:
      'border-emerald-400 bg-emerald-50 text-emerald-700 dark:border-emerald-500/60 dark:bg-emerald-500/10 dark:text-emerald-300',
  }
}

/** Props accepted by the {@link CopyButton} sub-component. */
interface CopyButtonProps {
  /** The text to copy to the clipboard. */
  value: string
}

/**
 * A square button that copies `value` to the clipboard and shows brief
 * "Copied!" feedback.
 *
 * @param props See {@link CopyButtonProps}.
 * @returns The copy button element.
 */
function CopyButton({ value }: CopyButtonProps): ReactElement {
  const [copied, setCopied] = useState(false)
  // Holds the feedback-reset timer so it can be cleared on re-copy/unmount.
  const timerRef = useRef<number | null>(null)

  // Clear any pending "Copied!" timer when the button unmounts.
  useEffect(() => {
    return () => {
      if (timerRef.current !== null) window.clearTimeout(timerRef.current)
    }
  }, [])

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      if (timerRef.current !== null) window.clearTimeout(timerRef.current)
      setCopied(true)
      timerRef.current = window.setTimeout(() => setCopied(false), 1500)
    } catch {
      setCopied(false)
    }
  }

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="border border-slate-300 bg-slate-50 px-2 py-1 font-mono text-[10px] font-bold uppercase tracking-wider text-slate-600 transition-colors hover:bg-slate-100 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800"
    >
      {copied ? 'Copied!' : 'Copy'}
    </button>
  )
}

/** Props accepted by the {@link HashRow} sub-component. */
interface HashRowProps {
  /** Display label (e.g. "Canvas Hash"). */
  label: string
  /** The computed hash value, or `null` when not yet calculated. */
  value: string | null
}

/**
 * Renders a single fingerprint result row: a label, the hash value, and a
 * copy-to-clipboard button (only shown when a value exists).
 *
 * @param props See {@link HashRowProps}.
 * @returns The result row element.
 */
function HashRow({ label, value }: HashRowProps): ReactElement {
  return (
    <div className="border border-slate-300 dark:border-slate-800">
      {/* Row header */}
      <div className="flex items-center justify-between gap-2 border-b border-slate-300 bg-slate-50 px-3 py-2 dark:border-slate-800 dark:bg-slate-950">
        <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-200">
          {label}
        </h3>
        {value ? <CopyButton value={value} /> : null}
      </div>

      {/* Row value */}
      <div className="px-3 py-3">
        {value ? (
          <code className="block break-all font-mono text-xs leading-relaxed text-slate-800 dark:text-slate-200">
            {value}
          </code>
        ) : (
          <p className="font-mono text-xs text-slate-400 dark:text-slate-500">
            Not calculated.
          </p>
        )}
      </div>
    </div>
  )
}

/**
 * Main fingerprint diagnostic panel.
 *
 * Presents the Canvas hash, Audio hash and an estimated fingerprint
 * uniqueness/entropy score with a sharp "CALCULATE FINGERPRINT" action button
 * and copy-to-clipboard buttons for each hash.
 *
 * @returns The fingerprint audit card element.
 */
export function FingerprintAuditCard(): ReactElement {
  const {
    canvasHash,
    audioHash,
    entropyScore,
    isCalculating,
    error,
    generateFingerprint,
  } = useFingerprint()

  // Derive the card status from the hook's state.
  const hasCalculated =
    canvasHash !== null || audioHash !== null || entropyScore !== null
  const status: Status = isCalculating
    ? 'calculating'
    : error
      ? 'error'
      : hasCalculated
        ? 'ready'
        : 'idle'
  const badge = STATUS_BADGES[status]
  const entropyMeta = entropyScore !== null ? entropyLabel(entropyScore) : null

  return (
    <section className="border border-slate-300 bg-white dark:border-slate-800 dark:bg-slate-900">
      {/* Card header: title + status badge */}
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-300 px-5 py-4 dark:border-slate-800">
        <div>
          <h2 className="font-mono text-base font-bold tracking-tight text-slate-900 dark:text-slate-100">
            Canvas &amp; Audio Fingerprint
          </h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Estimates how uniquely identifiable your device is from passive
            browser signals.
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
            onClick={generateFingerprint}
            disabled={isCalculating}
            className="border border-slate-900 bg-slate-900 px-4 py-2 font-mono text-xs font-bold uppercase tracking-wider text-white transition-colors hover:bg-slate-700 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-900 disabled:cursor-not-allowed disabled:opacity-60 dark:border-slate-100 dark:bg-slate-100 dark:text-slate-900 dark:hover:bg-slate-300"
          >
            {isCalculating ? 'Calculating…' : 'Calculate Fingerprint'}
          </button>
          <p className="font-mono text-xs text-slate-500 dark:text-slate-400">
            {isCalculating
              ? 'Rendering canvas + audio, then hashing…'
              : 'Runs entirely in your browser via the Canvas & Web Audio APIs.'}
          </p>
        </div>

        {/* Error banner */}
        {error && (
          <div className="mt-4 border border-red-300 bg-red-50 px-4 py-3 font-mono text-xs text-red-700 dark:border-red-500/50 dark:bg-red-500/10 dark:text-red-300">
            <span className="font-bold">ERROR:</span> {error}
          </div>
        )}

        {/* Results */}
        <div className="mt-6 grid gap-4">
          <HashRow label="Canvas Hash (SHA-256)" value={canvasHash} />
          <HashRow label="Audio Hash (SHA-256)" value={audioHash} />

          {/* Entropy score */}
          <div className="border border-slate-300 dark:border-slate-800">
            <div className="border-b border-slate-300 bg-slate-50 px-3 py-2 dark:border-slate-800 dark:bg-slate-950">
              <h3 className="font-mono text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-200">
                Fingerprint Uniqueness Score
              </h3>
            </div>
            <div className="flex items-center justify-between gap-3 px-3 py-3">
              {entropyScore !== null && entropyMeta ? (
                <>
                  <span className="font-mono text-xl font-bold text-slate-900 dark:text-slate-100">
                    {entropyScore}
                    <span className="ml-1 text-xs font-normal text-slate-500 dark:text-slate-400">
                      bits
                    </span>
                  </span>
                  <span
                    className={`border px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider ${entropyMeta.className}`}
                  >
                    {entropyMeta.label}
                  </span>
                </>
              ) : (
                <p className="font-mono text-xs text-slate-400 dark:text-slate-500">
                  Not calculated.
                </p>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Card footer */}
      <footer className="border-t border-slate-300 px-5 py-3 dark:border-slate-800">
        <p className="font-mono text-[11px] text-slate-400 dark:text-slate-500">
          SHA-256 via Web Crypto · 200×50 canvas · 44.1 kHz offline audio graph.
        </p>
      </footer>
    </section>
  )
}


