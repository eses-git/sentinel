import type { ReactElement } from 'react'
import { useTheme } from '../hooks/useTheme'

/**
 * Inline "sun" icon (shown in dark mode to indicate switching to light).
 * Inline SVG is used so the project stays dependency-free.
 *
 * @returns The sun icon element.
 */
function SunIcon(): ReactElement {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="h-4 w-4"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2" />
      <path d="M12 20v2" />
      <path d="m4.93 4.93 1.41 1.41" />
      <path d="m17.66 17.66 1.41 1.41" />
      <path d="M2 12h2" />
      <path d="M20 12h2" />
      <path d="m6.34 17.66-1.41 1.41" />
      <path d="m19.07 4.93-1.41 1.41" />
    </svg>
  )
}

/**
 * Inline "moon" icon (shown in light mode to indicate switching to dark).
 *
 * @returns The moon icon element.
 */
function MoonIcon(): ReactElement {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className="h-4 w-4"
      aria-hidden="true"
    >
      <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
    </svg>
  )
}

/**
 * Top navigation bar for the SENTINEL application.
 *
 * Renders:
 *   - The application title "SENTINEL // Network & Privacy Audit".
 *   - A sharp (square) dark/light theme toggle button backed by `useTheme`,
 *     which persists the user's choice and falls back to the OS preference.
 *
 * The bar is sticky so the theme control stays reachable while scrolling.
 *
 * @returns The navigation bar element.
 */
export function TopNavBar(): ReactElement {
  const { theme, toggleTheme } = useTheme()
  const isDark = theme === 'dark'

  return (
    <header className="sticky top-0 z-50 border-b border-slate-300 bg-white/95 backdrop-blur dark:border-slate-800 dark:bg-slate-950/95">
      <nav className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3 sm:px-6 lg:px-8">
        {/* Brand / title block */}
        <div className="flex items-center gap-3">
          <span
            className="grid h-9 w-9 place-items-center border border-slate-300 bg-slate-100 font-mono text-sm font-bold text-slate-900 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
            aria-hidden="true"
          >
            S
          </span>
          <div className="leading-tight">
            <h1 className="font-mono text-sm font-bold tracking-tight text-slate-900 sm:text-base dark:text-slate-100">
              SENTINEL
            </h1>
            <p className="font-mono text-[11px] text-slate-500 sm:text-xs dark:text-slate-400">
              {'// Network & Privacy Audit'}
            </p>
          </div>
        </div>

        {/* Theme switcher */}
        <button
          type="button"
          onClick={toggleTheme}
          aria-label={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
          title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
          className="flex items-center gap-2 border border-slate-300 bg-white px-3 py-2 font-mono text-xs font-semibold uppercase tracking-wider text-slate-700 transition-colors hover:bg-slate-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800"
        >
          {isDark ? <SunIcon /> : <MoonIcon />}
          <span>{isDark ? 'Light' : 'Dark'}</span>
        </button>
      </nav>
    </header>
  )
}
