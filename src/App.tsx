import type { ReactElement } from 'react'
import { TopNavBar } from './components/TopNavBar'
import { WebRTCAuditCard } from './components/WebRTCAuditCard'
import { FingerprintAuditCard } from './components/FingerprintAuditCard'
import { NetworkProbeCard } from './components/NetworkProbeCard'

/**
 * Root application component for SENTINEL — a browser security, privacy and
 * network leak audit tool.
 *
 * Mounts the top navigation bar (with the theme switcher) and the WebRTC
 * audit diagnostic panel inside a responsive, grid-lined layout.
 *
 * @returns The root application element.
 */
export default function App(): ReactElement {
  return (
    <div className="min-h-screen text-slate-900 dark:text-slate-100">
      {/* Sticky top navigation bar (brand + dark/light toggle). */}
      <TopNavBar />

      {/* Main content */}
      <main className="mx-auto w-full max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Intro / module header strip */}
        <section className="mb-6 border border-slate-300 bg-white p-5 dark:border-slate-800 dark:bg-slate-900">
          <p className="font-mono text-[11px] uppercase tracking-[0.25em] text-slate-500 dark:text-slate-400">
            Security Audit Suite
          </p>
          <h2 className="mt-1 font-mono text-xl font-bold text-slate-900 dark:text-slate-100">
            Browser Security &amp; Privacy Audit
          </h2>
          <p className="mt-2 max-w-3xl text-sm text-slate-600 dark:text-slate-300">
            SENTINEL probes the browser&apos;s WebRTC stack for real-IP leakage
            and measures Canvas + Web Audio fingerprint entropy to estimate how
            uniquely identifiable your device is.
          </p>
        </section>

        {/* Diagnostic panels (responsive grid: stacked → 2 columns on xl). */}
        <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
          <section aria-label="WebRTC audit module">
            <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.25em] text-slate-500 dark:text-slate-400">
              Module 01 · WebRTC
            </p>
            <WebRTCAuditCard />
          </section>
          <section aria-label="Fingerprint audit module">
            <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.25em] text-slate-500 dark:text-slate-400">
              Module 02 · Fingerprinting
            </p>
            <FingerprintAuditCard />
          </section>
          <section aria-label="Network probe module" className="xl:col-span-2">
            <p className="mb-2 font-mono text-[11px] uppercase tracking-[0.25em] text-slate-500 dark:text-slate-400">
              Module 03 · Network &amp; Headers
            </p>
            <NetworkProbeCard />
          </section>
        </div>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-300 py-6 dark:border-slate-800">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
          <p className="font-mono text-xs text-slate-500 dark:text-slate-400">
            SENTINEL — client-side diagnostics only. No data leaves your browser
            beyond standard STUN requests.
          </p>
        </div>
      </footer>
    </div>
  )
}
