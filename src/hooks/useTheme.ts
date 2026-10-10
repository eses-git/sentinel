import { useCallback, useEffect, useState } from 'react'

/**
 * The two visual themes supported by the application.
 * (A string union is used instead of an `enum` to comply with the project's
 * `erasableSyntaxOnly` TypeScript setting.)
 */
export type Theme = 'light' | 'dark'

/** localStorage key used to persist the user's explicit theme choice. */
const THEME_STORAGE_KEY = 'sentinel-theme'

/**
 * Reads the persisted theme from localStorage, if present and valid.
 *
 * @returns The stored `Theme`, or `null` when nothing valid is saved.
 */
function readStoredTheme(): Theme | null {
  try {
    const stored = localStorage.getItem(THEME_STORAGE_KEY)
    return stored === 'light' || stored === 'dark' ? stored : null
  } catch {
    // Storage can throw in privacy/incognito modes — treat it as "no choice".
    return null
  }
}

/**
 * Reports whether the operating system currently prefers a dark colour scheme.
 * Used as the fallback when the user has not made an explicit choice.
 *
 * @returns `true` when `prefers-color-scheme: dark` matches, otherwise `false`.
 */
function systemPrefersDark(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: dark)').matches
  )
}

/**
 * Resolves the initial theme using the "user choice → system preference"
 * priority order described in the project specification.
 *
 * @returns The resolved `Theme` value.
 */
function resolveInitialTheme(): Theme {
  return readStoredTheme() ?? (systemPrefersDark() ? 'dark' : 'light')
}

/**
 * Custom React hook that manages class-based dark/light mode.
 *
 * Behaviour:
 * 1. **Persistence** — the active theme is stored in `localStorage` so it
 *    survives page reloads.
 * 2. **System fallback** — when no stored choice exists, the OS
 *    `prefers-color-scheme` preference determines the initial theme.
 * 3. **DOM sync** — the hook adds/removes the `dark` class on `<html>`, which
 *    drives every Tailwind `dark:` utility (class-based dark mode).
 *
 * @returns `{ theme, toggleTheme }` where `theme` is the active theme and
 *          `toggleTheme` flips between light and dark.
 */
export function useTheme(): { theme: Theme; toggleTheme: () => void } {
  // Lazy-initialise so the first render already reflects the resolved theme.
  const [theme, setTheme] = useState<Theme>(() => resolveInitialTheme())

  // Keep <html>'s class list (and localStorage) in sync with `theme`.
  useEffect(() => {
    const root = document.documentElement

    if (theme === 'dark') {
      root.classList.add('dark')
    } else {
      root.classList.remove('dark')
    }

    // Persist the current choice for subsequent visits.
    try {
      localStorage.setItem(THEME_STORAGE_KEY, theme)
    } catch {
      // Storage may be unavailable — persistence is best-effort only.
    }
  }, [theme])

  // Stable callback that flips the theme; safe to pass to memoised children.
  const toggleTheme = useCallback(() => {
    setTheme((previous) => (previous === 'dark' ? 'light' : 'dark'))
  }, [])

  return { theme, toggleTheme }
}
