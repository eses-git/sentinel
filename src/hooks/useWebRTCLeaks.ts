import { useCallback, useEffect, useRef, useState } from 'react'

/**
 * Aggregated result of a single WebRTC leak scan.
 *
 * WebRTC (Web Real-Time Communication) can reveal a user's real network
 * topology — even through a VPN or proxy — because the ICE negotiation
 * process enumerates local and public interface addresses and shares them
 * with the remote peer.
 */
export interface WebRTCLeakReport {
  /**
   * Private / loopback / link-local IP addresses discovered on the host.
   * Includes `192.168.x.x`, `10.x.x.x`, `172.16-31.x.x` (RFC 1918),
   * `169.254.x.x` (link-local), `127.x.x.x` (loopback) and private IPv6
   * ranges (`::1`, `fc00::/7`, `fe80::/10`).
   */
  localIps: string[]

  /**
   * Public, internet-facing IP addresses discovered. A non-empty list while
   * a VPN/proxy is active indicates the real public address is leaking.
   */
  publicIps: string[]

  /**
   * mDNS hostnames (`.local`) the browser used to obfuscate local addresses.
   * These are opaque, per-session names that JavaScript cannot resolve to a
   * real IP; their presence still signals local-address disclosure.
   */
  mdnsHosts: string[]

  /** `true` while ICE candidates are actively being gathered. */
  isGathering: boolean

  /** Human-readable error message when a scan fails, otherwise `null`. */
  error: string | null

  /** Starts (or restarts) a fresh WebRTC leak scan. */
  startScan: () => void
}

/**
 * Public STUN servers used to force the browser to enumerate its interfaces.
 *
 * STUN ("Session Traversal Utilities for NAT") reflects the client's public IP
 * back to it — exactly the behaviour a leak test wants to observe. Only STUN
 * is configured; no TURN credentials are needed for this audit.
 */
const STUN_SERVERS: RTCIceServer[] = [
  { urls: 'stun:stun.l.google.com:19302' },
  { urls: 'stun:stun1.l.google.com:19302' },
  { urls: 'stun:stun.cloudflare.com:3478' },
]

/**
 * Fallback timeout (ms). If ICE gathering has not completed within this window
 * (for example, because STUN requests are dropped or stalled), the scan is
 * force-completed and the peer connection is released.
 */
const GATHER_TIMEOUT_MS = 5000

/**
 * Regex that tokenises an ICE candidate SDP line.
 *
 * Example line:
 *   `candidate:842163049 1 udp 1677729535 192.168.1.5 54321 typ srflx raddr 10.0.0.2 rport 54321`
 *
 * Capture groups (1-based):
 *   1 = foundation, 2 = component-id, 3 = transport, 4 = priority,
 *   5 = connection-address (the candidate's address),
 *   6 = port, 7 = candidate type (`host` | `srflx` | `prflx` | `relay`),
 *   8 = related address (`raddr`), 9 = related port (`rport`).
 */
const CANDIDATE_LINE_RE =
  /^candidate:(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+typ\s+(\S+)(?:\s+raddr\s+(\S+))?(?:\s+rport\s+(\d+))?/

/** Matches a dotted-decimal IPv4 address. */
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/** Matches a plausible IPv6 address (hex digits and colons only). */
const IPV6_RE = /^[0-9a-fA-F:]+$/

/**
 * Classification bucket for a discovered address string.
 * (A string union is used instead of an `enum` for `erasableSyntaxOnly`.)
 */
type AddressKind =
  | 'local-ipv4'
  | 'local-ipv6'
  | 'public-ipv4'
  | 'public-ipv6'
  | 'mdns'
  | 'ignored'

/**
 * Determines whether a dotted-decimal IPv4 address belongs to a private,
 * loopback, link-local or carrier-grade NAT (CGNAT) range.
 *
 * @param ip A candidate IPv4 string (e.g. `192.168.1.5`).
 * @returns `true` when the address is NOT publicly routable.
 */
function isLocalIPv4(ip: string): boolean {
  const match = IPV4_RE.exec(ip)
  if (!match) return false

  // Parse the four octets and reject malformed addresses (octet > 255).
  const octets = match.slice(1).map(Number)
  if (octets.some((octet) => octet > 255)) return false

  const [a, b] = octets
  return (
    a === 10 || // RFC 1918 — 10.0.0.0/8
    (a === 172 && b >= 16 && b <= 31) || // RFC 1918 — 172.16.0.0/12
    (a === 192 && b === 168) || // RFC 1918 — 192.168.0.0/16
    a === 127 || // Loopback — 127.0.0.0/8
    (a === 169 && b === 254) || // Link-local — 169.254.0.0/16
    (a === 100 && b >= 64 && b <= 127) // CGNAT — 100.64.0.0/10
  )
}

/**
 * Determines whether an IPv6 address is loopback, unspecified, link-local or
 * unique-local (i.e. not publicly routable).
 *
 * @param addr A candidate IPv6 string (e.g. `fe80::1`).
 * @returns `true` when the address is locally scoped.
 */
function isLocalIPv6(addr: string): boolean {
  const lower = addr.toLowerCase()
  return (
    lower === '::1' || // Loopback
    lower === '::' || // Unspecified
    lower.startsWith('fe8') || // Link-local fe80::/10
    lower.startsWith('fe9') ||
    lower.startsWith('fea') ||
    lower.startsWith('feb') ||
    lower.startsWith('fc') || // Unique-local fc00::/7
    lower.startsWith('fd')
  )
}

/**
 * Classifies a single raw address string into one of the {@link AddressKind}
 * buckets.
 *
 * @param raw The raw address (may be an IP, mDNS hostname, or empty).
 * @returns The appropriate {@link AddressKind} classification.
 */
function classifyAddress(raw: string): AddressKind {
  const addr = raw.trim()

  // Skip empty strings and the "unspecified" address that appears in `raddr`.
  if (addr === '' || addr === '0.0.0.0') return 'ignored'

  // mDNS obfuscation: browsers mask local addresses as `<uuid>.local`.
  if (addr.endsWith('.local')) return 'mdns'

  if (IPV4_RE.test(addr)) {
    return isLocalIPv4(addr) ? 'local-ipv4' : 'public-ipv4'
  }

  if (addr.includes(':') && IPV6_RE.test(addr)) {
    return isLocalIPv6(addr) ? 'local-ipv6' : 'public-ipv6'
  }

  return 'ignored'
}

/**
 * Parses an ICE candidate SDP line and returns the connection and related
 * addresses found within it.
 *
 * @param line The raw candidate string from `RTCIceCandidate.candidate`.
 * @returns An array of extracted address strings (may be empty).
 */
function parseCandidateLine(line: string): string[] {
  const match = CANDIDATE_LINE_RE.exec(line)
  if (!match) return []

  const addresses: string[] = []
  // Group 5 = connection address, group 8 = related address (`raddr`).
  if (match[5]) addresses.push(match[5])
  if (match[8]) addresses.push(match[8])
  return addresses
}

/**
 * Custom React hook that performs a WebRTC IP-leak scan.
 *
 * It instantiates an `RTCPeerConnection` targeting public STUN servers,
 * listens for `icecandidate` events, parses the candidate SDP lines, and
 * classifies every discovered address into local IPs, public IPs and mDNS
 * hostnames.
 *
 * @returns {@link WebRTCLeakReport} with the scan results and a `startScan`
 *          trigger.
 */
export function useWebRTCLeaks(): WebRTCLeakReport {
  const [localIps, setLocalIps] = useState<string[]>([])
  const [publicIps, setPublicIps] = useState<string[]>([])
  const [mdnsHosts, setMdnsHosts] = useState<string[]>([])
  const [isGathering, setIsGathering] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Holds the active RTCPeerConnection so it can be torn down between runs.
  const connectionRef = useRef<RTCPeerConnection | null>(null)
  // Guards state updates after unmount. NOTE: it must be reset to `false` when
  // a scan starts (see `startScan`) because React StrictMode runs the unmount
  // cleanup once during the initial mount, which would leave it stuck `true`.
  const cancelledRef = useRef(false)
  // Holds the fallback-timeout id so it can be cleared on teardown.
  const timeoutRef = useRef<number | null>(null)

  const startScan = useCallback(() => {
    // ---- 1. Tear down any previous scan -----------------------------------
    if (connectionRef.current) {
      connectionRef.current.onicecandidate = null
      connectionRef.current.onicegatheringstatechange = null
      connectionRef.current.close()
      connectionRef.current = null
    }
    if (timeoutRef.current !== null) {
      window.clearTimeout(timeoutRef.current)
      timeoutRef.current = null
    }

    // ---- 2. Reset the cancelled flag + UI state ----------------------------
    // Clear the "unmounted" guard so `finish()` can actually complete. This is
    // the key fix: React StrictMode's mount-time cleanup sets this flag `true`,
    // which would otherwise make `finish()` bail out forever and leave the UI
    // stuck in the "SCANNING…" state.
    cancelledRef.current = false

    setLocalIps([])
    setPublicIps([])
    setMdnsHosts([])
    setError(null)
    setIsGathering(true)

    // ---- 3. Verify WebRTC availability -------------------------------------
    // WebRTC requires a secure context (HTTPS / localhost) and modern browser.
    if (typeof window === 'undefined' || !('RTCPeerConnection' in window)) {
      setIsGathering(false)
      setError('WebRTC is not supported in this browser or secure context.')
      return
    }

    // ---- 4. Deduplicated collectors for this run ---------------------------
    const localSet = new Set<string>()
    const publicSet = new Set<string>()
    const mdnsSet = new Set<string>()

    // Helper: classify a raw address and add it to the appropriate bucket.
    const collect = (raw: string | null | undefined) => {
      if (!raw) return
      const kind = classifyAddress(raw)
      if (kind === 'local-ipv4' || kind === 'local-ipv6') {
        localSet.add(raw.trim())
      } else if (kind === 'public-ipv4' || kind === 'public-ipv6') {
        publicSet.add(raw.trim())
      } else if (kind === 'mdns') {
        mdnsSet.add(raw.trim())
      }
    }

    // Helper: push the current buckets into React state (sorted + deduped).
    const commit = () => {
      setLocalIps(Array.from(localSet).sort())
      setPublicIps(Array.from(publicSet).sort())
      setMdnsHosts(Array.from(mdnsSet).sort())
    }

    // Helper: finish the scan. Commits results, stops the "gathering" state,
    // clears the fallback timeout and ALWAYS closes the peer connection to
    // release sockets. It is idempotent, so it is safe to call from the
    // `null`-candidate event, the gathering-state event, the timeout, and the
    // error path without any double-teardown.
    const finish = () => {
      // If the component unmounted mid-scan, don't touch React state.
      if (cancelledRef.current) return

      // Push the latest buckets into React state.
      commit()
      setIsGathering(false)

      // Clear the fallback timeout so it can't fire after completion.
      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current)
        timeoutRef.current = null
      }

      // Always close the connection to prevent socket/memory leaks.
      if (connectionRef.current) {
        connectionRef.current.onicecandidate = null
        connectionRef.current.onicegatheringstatechange = null
        connectionRef.current.close()
        connectionRef.current = null
      }
    }

    // ---- 5. Create the peer connection -------------------------------------
    let pc: RTCPeerConnection
    try {
      pc = new RTCPeerConnection({ iceServers: STUN_SERVERS })
    } catch (err) {
      setIsGathering(false)
      setError(
        err instanceof Error
          ? err.message
          : 'Failed to create RTCPeerConnection.',
      )
      return
    }
    connectionRef.current = pc

    // ---- 6. ICE candidate handler ------------------------------------------
    // Fired for every gathered candidate; `null` signals the end of gathering.
    pc.onicecandidate = (event: RTCPeerConnectionIceEvent) => {
      const candidate = event.candidate
      if (candidate === null) {
        finish()
        return
      }

      // Parse the raw SDP line (connection + related addresses).
      parseCandidateLine(candidate.candidate).forEach(collect)
      // Also read the structured fields — some browsers populate only one.
      collect(candidate.address)
      collect(candidate.relatedAddress)

      // Live-update the UI as candidates stream in.
      commit()
    }

    // ---- 7. Gathering-state handler (belt-and-braces completion) ------------
    pc.onicegatheringstatechange = () => {
      if (pc.iceGatheringState === 'complete') finish()
    }

    // ---- 8. Safety timeout --------------------------------------------------
    // Some browsers/network topologies stall; force-stop after the limit.
    timeoutRef.current = window.setTimeout(finish, GATHER_TIMEOUT_MS)

    // ---- 9. Kick off ICE gathering ------------------------------------------
    // A data channel forces candidate collection without mic/camera access.
    pc.createDataChannel('sentinel-probe')
    pc.createOffer()
      .then((offer) => pc.setLocalDescription(offer))
      .catch((err) => {
        finish()
        setError(
          err instanceof Error ? err.message : 'Failed to start ICE gathering.',
        )
      })

  }, [])

  // Mount/unmount lifecycle. On mount we re-arm the guard (this undoes the
  // StrictMode dev-only simulated unmount); on unmount we mark the hook as
  // cancelled and release the peer connection to prevent leaks.
  useEffect(() => {
    cancelledRef.current = false

    return () => {
      cancelledRef.current = true

      if (timeoutRef.current !== null) {
        window.clearTimeout(timeoutRef.current)
        timeoutRef.current = null
      }

      if (connectionRef.current) {
        connectionRef.current.onicecandidate = null
        connectionRef.current.onicegatheringstatechange = null
        connectionRef.current.close()
        connectionRef.current = null
      }
    }
  }, [])

  return { localIps, publicIps, mdnsHosts, isGathering, error, startScan }

}


