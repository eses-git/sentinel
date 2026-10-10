import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Result of a single browser-fingerprint calculation.
 *
 * Browser fingerprinting combines stable signals (rendered pixels, audio
 * processing, the user-agent string and screen metrics) to uniquely identify
 * a device across sessions. This report exposes the two most distinctive
 * passive signals — Canvas and Web Audio — as SHA-256 digests, plus an
 * estimated entropy score.
 */
export interface FingerprintReport {
  /** 64-character lowercase hex SHA-256 of the rendered canvas pixels, or `null`. */
  canvasHash: string | null

  /** 64-character lowercase hex SHA-256 of the rendered audio sum, or `null`. */
  audioHash: string | null

  /**
   * Estimated uniqueness/entropy (in bits) derived from the user-agent, screen
   * resolution, timezone, canvas hash and audio hash, or `null` when not yet
   * calculated.
   */
  entropyScore: number | null

  /** `true` while the canvas + audio fingerprints are being computed. */
  isCalculating: boolean

  /** Human-readable error message when the calculation fails, otherwise `null`. */
  error: string | null

  /** Triggers (or re-triggers) a fresh fingerprint calculation. */
  generateFingerprint: () => void
}

/**
 * Off-screen canvas dimensions. 200×50 is a widely used fingerprinting size:
 * large enough to expose anti-aliasing differences, small enough to be cheap.
 */
const CANVAS_WIDTH = 200
const CANVAS_HEIGHT = 50

/** Audio graph sample rate (Hz). 44.1 kHz is the de-facto browser standard. */
const AUDIO_SAMPLE_RATE = 44100

/** Length of the rendered audio buffer in seconds (1s ≈ 44,100 samples). */
const AUDIO_DURATION_SECONDS = 1

/**
 * Computes the Shannon entropy of a string, measured in bits **per symbol**.
 *
 * @param value The input string.
 * @returns The per-symbol entropy (0 for an empty or perfectly uniform string).
 */
function shannonEntropy(value: string): number {
  if (!value) return 0

  // Count the occurrences of each distinct character.
  const counts = new Map<string, number>()
  for (const char of value) {
    counts.set(char, (counts.get(char) ?? 0) + 1)
  }

  // H = -Σ p(x) · log2(p(x))
  let entropy = 0
  for (const count of counts.values()) {
    const probability = count / value.length
    entropy -= probability * Math.log2(probability)
  }
  return entropy
}

/**
 * Hashes a binary payload with SHA-256 and returns the lowercase hex digest.
 *
 * `crypto.subtle.digest` is only available in secure contexts (HTTPS /
 * localhost); the caller should verify its availability before invoking.
 *
 * @param bytes The binary payload to hash.
 * @returns A 64-character hex string.
 */
async function sha256Hex(bytes: Uint8Array): Promise<string> {
  // `crypto.subtle.digest` expects a `BufferSource` backed by a plain
  // `ArrayBuffer` (not a `SharedArrayBuffer`), so copy the bytes into a fresh
  // ArrayBuffer-backed view first.
  const copy = new Uint8Array(bytes.length)
  copy.set(bytes)

  const digest = await crypto.subtle.digest('SHA-256', copy)
  // Convert the raw 32-byte digest into 2-digit hex pairs.
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Renders a hidden off-screen canvas with shapes, gradients, arcs and text,
 * then returns the raw RGBA pixel buffer.
 *
 * Different browsers, OSes and GPU/driver stacks rasterise anti-aliased curves
 * and text with subtly different pixel values; hashing those pixels yields a
 * stable, high-entropy fingerprint.
 *
 * @returns The RGBA pixel bytes (200 × 50 × 4 = 40,000 bytes).
 */
function renderCanvasFingerprint(): Uint8Array {
  const canvas = document.createElement('canvas')
  canvas.width = CANVAS_WIDTH
  canvas.height = CANVAS_HEIGHT

  const ctx = canvas.getContext('2d')
  if (!ctx) throw new Error('Canvas 2D context is unavailable.')

  // 1. Solid background fill.
  ctx.fillStyle = '#1e1e2e'
  ctx.fillRect(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT)

  // 2. Diagonal linear gradient (exercises colour interpolation).
  const gradient = ctx.createLinearGradient(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT)
  gradient.addColorStop(0, '#0ea5e9')
  gradient.addColorStop(0.5, '#a855f7')
  gradient.addColorStop(1, '#f59e0b')
  ctx.fillStyle = gradient
  ctx.fillRect(8, 8, CANVAS_WIDTH - 16, CANVAS_HEIGHT - 16)

  // 3. Anti-aliased text (font rasterisation is highly platform-dependent).
  ctx.font = 'bold 16px "Arial", sans-serif'
  ctx.textBaseline = 'alphabetic'
  ctx.fillStyle = '#ffffff'
  ctx.fillText('SENTINEL', 16, 34)

  // 4. Anti-aliased arc (circle) strokes.
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.85)'
  ctx.lineWidth = 1.5
  ctx.beginPath()
  ctx.arc(CANVAS_WIDTH - 34, CANVAS_HEIGHT / 2, 12, 0, Math.PI * 2, true)
  ctx.stroke()

  // 5. Geometric shapes (triangle + rectangle) with partial transparency.
  ctx.fillStyle = 'rgba(0, 0, 0, 0.45)'
  ctx.beginPath()
  ctx.moveTo(92, 8)
  ctx.lineTo(122, 8)
  ctx.lineTo(107, 22)
  ctx.closePath()
  ctx.fill()
  ctx.fillRect(96, 30, 18, 6)

  // Extract the raw pixel buffer. `getImageData().data` is a Uint8ClampedArray;
  // copy it into a plain Uint8Array for hashing.
  const pixels = ctx.getImageData(0, 0, CANVAS_WIDTH, CANVAS_HEIGHT).data
  return Uint8Array.from(pixels)
}

/**
 * Returns the `OfflineAudioContext` constructor, with a legacy WebKit-prefixed
 * fallback. The prefixed alias is not part of lib.dom.d.ts, so it is read via
 * a narrow cast.
 *
 * @returns The constructor, or `null` when Web Audio is unsupported.
 */
function getOfflineAudioContextCtor(): typeof OfflineAudioContext | null {
  if (typeof OfflineAudioContext !== 'undefined') return OfflineAudioContext

  const legacy = (
    window as unknown as {
      webkitOfflineAudioContext?: typeof OfflineAudioContext
    }
  ).webkitOfflineAudioContext
  return legacy ?? null
}

/**
 * Renders a short, deterministic audio graph and returns a binary payload
 * derived from the sum of its floating-point samples.
 *
 * The graph is a triangle-wave oscillator fed through a dynamics compressor.
 * The compressor's internal floating-point DSP runs slightly differently on
 * every browser/OS/audio-stack combination, so the summed samples — though
 * inaudible and sub-microsecond — differ measurably across devices.
 *
 * @returns An 8-byte little-endian float64 payload encoding the sample sum.
 */
async function renderAudioFingerprint(): Promise<Uint8Array> {
  const OfflineCtor = getOfflineAudioContextCtor()
  if (!OfflineCtor) throw new Error('OfflineAudioContext is not supported.')

  // 1 channel, ~1 second of samples at 44.1 kHz.
  const context = new OfflineCtor(
    1,
    AUDIO_SAMPLE_RATE * AUDIO_DURATION_SECONDS,
    AUDIO_SAMPLE_RATE,
  )

  // Triangle oscillator at a fixed high frequency.
  const oscillator = context.createOscillator()
  oscillator.type = 'triangle'
  oscillator.frequency.value = 10000

  // Dynamics compressor — the node whose DSP produces the platform-specific
  // floating-point differences we measure.
  const compressor = context.createDynamicsCompressor()
  compressor.threshold.value = -50
  compressor.knee.value = 40
  compressor.ratio.value = 12
  compressor.attack.value = 0
  compressor.release.value = 0.25

  oscillator.connect(compressor)
  compressor.connect(context.destination)

  oscillator.start(0)

  // Render the graph offline and read the mono channel.
  const rendered = await context.startRendering()
  const channel = rendered.getChannelData(0)

  // Sum every floating-point sample into a single scalar.
  let sum = 0
  for (let i = 0; i < channel.length; i += 1) {
    sum += channel[i]
  }

  // Serialise the sum as little-endian float64 (8 bytes) for hashing.
  const payload = new ArrayBuffer(8)
  new DataView(payload).setFloat64(0, sum, true)
  return new Uint8Array(payload)
}

/**
 * Estimates the total identifying entropy (in bits) contributed by the key
 * fingerprint signals.
 *
 * The figures are documented heuristics based on publicly reported browser
 * fingerprinting studies (e.g. EFF's Panopticlick); they are an **estimate**,
 * not an exact measurement.
 *
 * @param canvasHash The computed canvas hash, or `null`.
 * @param audioHash  The computed audio hash, or `null`.
 * @returns An estimated entropy score in bits (0–256).
 */
function estimateEntropyBits(
  canvasHash: string | null,
  audioHash: string | null,
): number {
  let bits = 0

  // --- User-Agent: Shannon entropy (bits/char) scaled + clamped (~6–15 bits).
  const uaEntropy = shannonEntropy(navigator.userAgent)
  bits += Math.min(Math.max(uaEntropy * 4, 6), 15)

  // --- Screen resolution: log-scale estimate, capped at 12 bits.
  const widthBits = Math.log2(Math.max(screen.width, 1))
  const heightBits = Math.log2(Math.max(screen.height, 1))
  bits += Math.min(widthBits + heightBits, 12)

  // --- Timezone: ~40 distinct UTC offsets worldwide → log2(40) ≈ 5.3 bits.
  bits += Math.log2(40)

  // --- Canvas fingerprint: typically ~9 bits of identifying information.
  if (canvasHash) bits += 9

  // --- Audio fingerprint: typically ~7 bits of identifying information.
  if (audioHash) bits += 7

  // SHA-256 caps the theoretical maximum at 256 bits.
  return Math.min(bits, 256)
}

/**
 * Custom React hook that calculates browser fingerprints.
 *
 * It renders an off-screen canvas and an offline audio graph, hashes both
 * binary payloads with SHA-256, and estimates an entropy score from those
 * hashes plus the user-agent, screen resolution and timezone.
 *
 * @returns {@link FingerprintReport} with the hashes, entropy score and a
 *          `generateFingerprint` trigger.
 */
export function useFingerprint(): FingerprintReport {
  const [canvasHash, setCanvasHash] = useState<string | null>(null)
  const [audioHash, setAudioHash] = useState<string | null>(null)
  const [entropyScore, setEntropyScore] = useState<number | null>(null)
  const [isCalculating, setIsCalculating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Tracks whether the component is still mounted (prevents setState after
  // unmount). Re-armed in the effect body to survive StrictMode's dev remount.
  const mountedRef = useRef(false)
  // Monotonic run id: only the most recent run may write results to state.
  const runIdRef = useRef(0)

  const generateFingerprint = useCallback(() => {
    // Invalidate any in-flight run and capture this run's id.
    const runId = ++runIdRef.current

    // Reset UI state.
    setCanvasHash(null)
    setAudioHash(null)
    setEntropyScore(null)
    setError(null)
    setIsCalculating(true)

    // Run the work asynchronously (canvas is synchronous, audio + hashing await).
    void (async () => {
      try {
        // Web Crypto is required for hashing and needs a secure context.
        if (typeof crypto === 'undefined' || !crypto.subtle) {
          throw new Error('Web Crypto API (crypto.subtle) is unavailable.')
        }

        // Compute both binary payloads independently; a failure in one should
        // not prevent the other from being reported.
        let canvasBytes: Uint8Array | null = null
        let audioBytes: Uint8Array | null = null

        try {
          canvasBytes = renderCanvasFingerprint()
        } catch {
          canvasBytes = null // canvas fingerprinting failed — continue.
        }

        try {
          audioBytes = await renderAudioFingerprint()
        } catch {
          audioBytes = null // audio fingerprinting failed — continue.
        }

        // Hash whichever payloads succeeded.
        const nextCanvasHash = canvasBytes ? await sha256Hex(canvasBytes) : null
        const nextAudioHash = audioBytes ? await sha256Hex(audioBytes) : null

        // Discard stale results (a newer run supersedes this one).
        if (runId !== runIdRef.current) return
        if (!mountedRef.current) return

        setCanvasHash(nextCanvasHash)
        setAudioHash(nextAudioHash)
        setEntropyScore(
          Math.round(
            estimateEntropyBits(nextCanvasHash, nextAudioHash) * 10,
          ) / 10,
        )
      } catch (err) {
        if (runId !== runIdRef.current) return
        if (!mountedRef.current) return
        setError(
          err instanceof Error
            ? err.message
            : 'Fingerprint calculation failed.',
        )
      } finally {
        if (runId === runIdRef.current && mountedRef.current) {
          setIsCalculating(false)
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

  return {
    canvasHash,
    audioHash,
    entropyScore,
    isCalculating,
    error,
    generateFingerprint,
  }
}


