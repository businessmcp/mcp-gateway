// SSRF guard for server-side fetches to user-supplied URLs.
//
// Dependency-free by design: two Node builtins, nothing else. A guard that drags
// in a framework is a guard people copy-paste instead of importing, and then it
// drifts.

import { lookup } from 'node:dns/promises'
import { isIP } from 'node:net'

/** Is this dotted-quad IPv4 in a reserved range? */
function blockedV4(a: number, b: number): boolean {
  if (a === 0 || a === 127 || a === 10) return true // this-host, loopback, private
  if (a === 169 && b === 254) return true // link-local incl. 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true // private
  if (a === 192 && b === 168) return true // private
  if (a === 100 && b >= 64 && b <= 127) return true // CGNAT
  if (a >= 224) return true // multicast (224/4) + reserved (240/4)
  // IETF special-purpose ranges that are routable-looking but never a legitimate
  // fetch target. 192.0.0.0/24 and 192.88.99.0/24 (6to4 relay anycast) can reach real
  // infrastructure; 198.18.0.0/15 is benchmark space; the three TEST-NET blocks are
  // documentation-only and a request to one is always either a mistake or a probe.
  if (a === 192 && b === 0) return true // 192.0.0.0/24 (IETF) + 192.0.2.0/24 TEST-NET-1
  if (a === 192 && b === 88) return true // 192.88.99.0/24 6to4 relay anycast
  if (a === 198 && (b === 18 || b === 19)) return true // 198.18.0.0/15 benchmark
  if (a === 198 && b === 51) return true // 198.51.100.0/24 TEST-NET-2
  if (a === 203 && b === 0) return true // 203.0.113.0/24 TEST-NET-3
  return false
}

/**
 * Expand an IPv6 literal to its eight 16-bit groups, or null if unparseable.
 *
 * We decode rather than prefix-match because IPv6 has many textual spellings of
 * the same address and the WHATWG URL parser normalizes them: `[::ffff:127.0.0.1]`
 * comes back as `::ffff:7f00:1`, in HEX. A guard that string-matches the dotted
 * form therefore never fires on a URL a caller actually passed.
 */
export function v6Groups(input: string): number[] | null {
  let s = input
  // A trailing dotted quad occupies the last two groups.
  const dotted = s.match(/^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/)
  if (dotted) {
    const o = dotted[2].split('.').map(Number)
    if (o.some((n) => n > 255)) return null
    s = `${dotted[1]}${(((o[0] << 8) | o[1]) >>> 0).toString(16)}:${(((o[2] << 8) | o[3]) >>> 0).toString(16)}`
  }
  const halves = s.split('::')
  if (halves.length > 2) return null
  const head = halves[0] ? halves[0].split(':') : []
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : []
  let parts: string[]
  if (halves.length === 2) {
    const fill = 8 - head.length - tail.length
    if (fill < 0) return null
    parts = [...head, ...Array<string>(fill).fill('0'), ...tail]
  } else {
    parts = head
  }
  if (parts.length !== 8) return null
  const groups = parts.map((p) => (/^[0-9a-f]{1,4}$/i.test(p) ? parseInt(p, 16) : NaN))
  return groups.some((n) => Number.isNaN(n)) ? null : groups
}

/**
 * Reserved-range check over decoded IPv6 groups.
 *
 * Every transition mechanism that embeds an IPv4 address is unwrapped and the
 * embedded address checked, because otherwise each is a way to spell
 * 169.254.169.254 that looks like an ordinary v6 address.
 */
function blockedV6(g: number[]): boolean {
  const topZero = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0
  // :: (unspecified) and ::1 (loopback)
  if (topZero && g[5] === 0 && g[6] === 0 && (g[7] === 0 || g[7] === 1)) return true
  // ::ffff:a.b.c.d — IPv4-mapped
  if (topZero && g[5] === 0xffff) return blockedV4(g[6] >> 8, g[6] & 0xff)
  // ::a.b.c.d — IPv4-compatible (deprecated, still resolvable)
  if (topZero && g[5] === 0) return blockedV4(g[6] >> 8, g[6] & 0xff)
  // 64:ff9b::/96 — NAT64
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0)
    return blockedV4(g[6] >> 8, g[6] & 0xff)
  // 2002::/16 — 6to4, embeds the v4 in groups 1-2
  if (g[0] === 0x2002) return blockedV4(g[1] >> 8, g[1] & 0xff)
  // ::ffff:0:a.b.c.d — RFC 2765 IPv4-TRANSLATED (::ffff:0:0/96). Distinct from the
  // IPv4-mapped form above: the 0xffff sits in group 4, not 5, so the `topZero` test
  // (which requires g[4] === 0) skipped every unwrap branch and let it through.
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0xffff && g[5] === 0)
    return blockedV4(g[6] >> 8, g[6] & 0xff)
  if ((g[0] & 0xffff) === 0x2001 && g[1] === 0) return true // 2001::/32 Teredo
  if ((g[0] & 0xffc0) === 0xfec0) return true // fec0::/10 deprecated site-local
  if ((g[0] & 0xfe00) === 0xfc00) return true // fc00::/7 ULA
  if ((g[0] & 0xffc0) === 0xfe80) return true // fe80::/10 link-local
  if ((g[0] & 0xff00) === 0xff00) return true // ff00::/8 multicast
  return false
}

// True only for an IP literal / resolved address in a reserved range.
export function isBlockedIp(ip: string): boolean {
  const v = ip.toLowerCase().replace(/^\[|\]$/g, '').replace(/%.*$/, '')
  if (isIP(v) === 4) {
    const [a, b] = v.split('.').map(Number)
    return blockedV4(a, b)
  }
  const groups = v6Groups(v)
  // Unparseable input fails CLOSED: an address we cannot decode is one we
  // cannot vouch for. Note this is reachable in normal operation, not just on
  // hostile input — isPublicHttpUrl passes DNS results straight through, so a
  // resolver returning something this parser does not understand is refused
  // rather than assumed public.
  if (!groups) return true
  return blockedV6(groups)
}

// Allow only http(s) to a public host. Checks the literal host and every
// resolved address (best-effort DNS-rebinding defense; a TOCTOU rebind between
// this check and the actual fetch is a small residual risk we accept for now).
export async function isPublicHttpUrl(raw: string): Promise<boolean> {
  let u: URL
  try {
    u = new URL(raw)
  } catch {
    return false
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '')
  if (host === 'localhost' || host.endsWith('.localhost') || host === 'metadata.google.internal')
    return false
  if (isIP(host)) return !isBlockedIp(host)
  try {
    const addrs = await lookup(host, { all: true })
    return addrs.length > 0 && addrs.every((a) => !isBlockedIp(a.address))
  } catch {
    return false
  }
}

/** Shared rejection copy, so every entry point refuses identically. */
export const SSRF_REJECTION = 'The URL must be http(s) and resolve to a public host'
