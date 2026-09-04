// Pure decision-making for talking to upstream MCP servers: why a connection
// failed, how to name an aggregated tool, how to parse configured headers.
//
// Zero imports, so it is trivially unit-testable and carries no runtime weight.

/**
 * Why an upstream server could not be reached. Previously every one of these
 * collapsed into `null` and the server simply vanished from the tool list with
 * no explanation anywhere — auth failures, dead hosts and unsupported transports
 * were indistinguishable to the user.
 */
export type UpstreamFailureReason =
  | 'auth_required'
  | 'transport_unsupported'
  | 'timeout'
  | 'blocked_host'
  | 'unreachable'

export type UpstreamFailure = { reason: UpstreamFailureReason; detail: string }

const MAX_DETAIL = 300

/** Map a thrown error from the MCP client onto a reason a human can act on. */
export function classifyUpstreamError(err: unknown): UpstreamFailure {
  const raw = err instanceof Error ? err.message : String(err ?? 'unknown error')
  const detail = raw.slice(0, MAX_DETAIL)
  const m = raw.toLowerCase()

  // 401/403, or the SDK's auth flow throwing because we pass no authProvider.
  if (
    /\b401\b|\b403\b/.test(m) ||
    m.includes('unauthorized') ||
    m.includes('forbidden') ||
    m.includes('invalid_token') ||
    m.includes('www-authenticate')
  ) {
    return { reason: 'auth_required', detail }
  }
  if (m.includes('timed out') || m.includes('timeout') || m.includes('aborted')) {
    return { reason: 'timeout', detail }
  }
  // Our own SSRF guard, or a host that resolves somewhere we refuse to fetch.
  if (m.includes('public host') || m.includes('blocked') || m.includes('ssrf')) {
    return { reason: 'blocked_host', detail }
  }
  // A server that only speaks the legacy HTTP+SSE transport answers the
  // streamable-HTTP handshake with a 4xx/405 or a non-JSON body.
  if (
    /\b405\b|\b406\b|\b415\b/.test(m) ||
    m.includes('method not allowed') ||
    m.includes('unsupported') ||
    m.includes('protocol version') ||
    m.includes('not valid json') ||
    m.includes('unexpected token')
  ) {
    return { reason: 'transport_unsupported', detail }
  }
  return { reason: 'unreachable', detail }
}

const FAILURE_MESSAGE: Record<UpstreamFailureReason, string> = {
  auth_required: 'rejected our credentials. Check the bearer token on this connection.',
  transport_unsupported:
    'did not complete an MCP handshake over either streamable HTTP or SSE. Check the URL points at an MCP endpoint.',
  timeout: 'did not respond in time.',
  blocked_host: 'resolves to a non-public host, so we refuse to fetch it.',
  unreachable: 'could not be reached.',
}

/** One sentence a user can act on, for the Connections card and tool errors. */
export function describeFailure(label: string, failure: UpstreamFailure): string {
  return `"${label}" ${FAILURE_MESSAGE[failure.reason]}`
}

/**
 * Parse a textarea of `Key: Value` lines into a header map.
 *
 * Values are validated again by `sanitizeHeaders` at send time — this is the
 * input-shaping half, that one is the security half.
 */
export function parseHeaderLines(raw: string | null | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of (raw ?? '').split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    const idx = trimmed.indexOf(':')
    if (idx <= 0) continue
    const key = trimmed.slice(0, idx).trim()
    const value = trimmed.slice(idx + 1).trim()
    if (key && value) out[key] = value
  }
  return out
}

/** FNV-1a, so truncated names disambiguate deterministically without a crypto import. */
function hash8(input: string): string {
  let h = 0x811c9dc5
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i)
    h = Math.imul(h, 0x01000193) >>> 0
  }
  return h.toString(16).padStart(8, '0')
}

export const MAX_TOOL_NAME = 64

/**
 * Namespaced upstream tool name, `ext_<slug>_<tool>`.
 *
 * The old version blindly `.slice(0, 64)`-ed, so two long tool names on one
 * server could truncate to the SAME string — and the dispatcher resolves by
 * `find()`, meaning a call would silently run the WRONG upstream tool. Names
 * that need truncating now carry a hash of the full name, and `taken` guards
 * the residual case.
 */
export function namespacedToolName(slug: string, toolName: string, taken: Set<string>): string {
  const base = `ext_${slug}_${toolName}`.replace(/[^a-zA-Z0-9_-]/g, '_')
  let name =
    base.length <= MAX_TOOL_NAME
      ? base
      : `${base.slice(0, MAX_TOOL_NAME - 9)}_${hash8(`${slug}/${toolName}`)}`
  // Different upstream tools that still collide (same slug+name after
  // sanitising) get a deterministic counter rather than overwriting each other.
  if (taken.has(name)) {
    for (let i = 2; ; i++) {
      const suffix = `_${i}`
      const candidate = `${name.slice(0, MAX_TOOL_NAME - suffix.length)}${suffix}`
      if (!taken.has(candidate)) {
        name = candidate
        break
      }
    }
  }
  taken.add(name)
  return name
}

/** Which wire protocol an upstream speaks. Persisted so we skip the probe next time. */
export type UpstreamTransport = 'http' | 'sse'

/**
 * The transports to try, in order, for an upstream.
 *
 * MCP's 2026-07-28 revision dropped legacy HTTP+SSE for *servers*, but plenty of
 * third-party servers we connect *to* still only speak it — so an unknown
 * upstream is probed streamable-HTTP first, then SSE. A known one is not
 * re-probed, which is the whole reason the transport is persisted.
 */
export function transportOrder(known?: UpstreamTransport): UpstreamTransport[] {
  if (known === 'sse') return ['sse']
  if (known === 'http') return ['http']
  return ['http', 'sse']
}
