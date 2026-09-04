import { describe, expect, it } from 'vitest'
import {
  MAX_TOOL_NAME,
  classifyUpstreamError,
  describeFailure,
  namespacedToolName,
  transportOrder,
  parseHeaderLines,
} from './upstream-logic'

describe('classifyUpstreamError', () => {
  it.each([
    ['HTTP 401 Unauthorized', 'auth_required'],
    ['Server returned 403', 'auth_required'],
    ['invalid_token', 'auth_required'],
    ['WWW-Authenticate: Bearer realm="x"', 'auth_required'],
    ['Request timed out after 8000ms', 'timeout'],
    ['The operation was aborted', 'timeout'],
    ['The URL must resolve to a public host', 'blocked_host'],
    ['HTTP 405 Method Not Allowed', 'transport_unsupported'],
    ['Unsupported protocol version', 'transport_unsupported'],
    ['Unexpected token < in JSON at position 0', 'transport_unsupported'],
    ['fetch failed', 'unreachable'],
    ['ECONNREFUSED', 'unreachable'],
  ])('classifies %s', (message, reason) => {
    expect(classifyUpstreamError(new Error(message)).reason).toBe(reason)
  })

  it('handles non-Error throws without losing the message', () => {
    expect(classifyUpstreamError('boom')).toEqual({ reason: 'unreachable', detail: 'boom' })
    expect(classifyUpstreamError(undefined).reason).toBe('unreachable')
  })

  it('truncates the detail so a chatty upstream cannot bloat the stored config', () => {
    const failure = classifyUpstreamError(new Error('x'.repeat(5000)))
    expect(failure.detail.length).toBe(300)
  })
})

describe('describeFailure', () => {
  it('names the server and says what to do', () => {
    const msg = describeFailure('Acme', { reason: 'auth_required', detail: '401' })
    expect(msg).toContain('Acme')
    expect(msg).toContain('bearer token')
  })
})

describe('parseHeaderLines', () => {
  it('parses Key: Value lines', () => {
    expect(parseHeaderLines('X-API-Key: abc\nX-Tenant: acme')).toEqual({
      'X-API-Key': 'abc',
      'X-Tenant': 'acme',
    })
  })

  it('ignores blanks, comments and malformed lines', () => {
    expect(parseHeaderLines('\n# a comment\nnocolon\n: novalue\nX-Ok: yes\n')).toEqual({
      'X-Ok': 'yes',
    })
  })

  it('keeps colons inside the value', () => {
    expect(parseHeaderLines('X-Url: https://example.com/x')).toEqual({
      'X-Url': 'https://example.com/x',
    })
  })

  it('returns an empty map for empty input', () => {
    expect(parseHeaderLines(null)).toEqual({})
    expect(parseHeaderLines(undefined)).toEqual({})
    expect(parseHeaderLines('   ')).toEqual({})
  })
})

describe('namespacedToolName', () => {
  it('namespaces and sanitises', () => {
    expect(namespacedToolName('acme', 'do.thing', new Set())).toBe('ext_acme_do_thing')
  })

  it('never exceeds the name cap', () => {
    const name = namespacedToolName('a'.repeat(40), 'b'.repeat(60), new Set())
    expect(name.length).toBeLessThanOrEqual(MAX_TOOL_NAME)
  })

  // The bug this exists for: two long names used to truncate to an identical
  // string, and the dispatcher resolves by find(), so a call ran the WRONG tool.
  it('keeps over-long names distinct instead of colliding', () => {
    const taken = new Set<string>()
    const a = namespacedToolName('server', `${'x'.repeat(70)}_alpha`, taken)
    const b = namespacedToolName('server', `${'x'.repeat(70)}_beta`, taken)
    expect(a).not.toBe(b)
    expect(a.length).toBeLessThanOrEqual(MAX_TOOL_NAME)
    expect(b.length).toBeLessThanOrEqual(MAX_TOOL_NAME)
  })

  it('is deterministic across runs', () => {
    const first = namespacedToolName('server', 'y'.repeat(80), new Set())
    const second = namespacedToolName('server', 'y'.repeat(80), new Set())
    expect(first).toBe(second)
  })

  it('disambiguates exact duplicates after sanitising', () => {
    const taken = new Set<string>()
    // Both sanitise to ext_acme_a_b.
    expect(namespacedToolName('acme', 'a.b', taken)).toBe('ext_acme_a_b')
    expect(namespacedToolName('acme', 'a/b', taken)).toBe('ext_acme_a_b_2')
  })
})

describe('transportOrder', () => {
  it('probes streamable HTTP first when the transport is unknown', () => {
    expect(transportOrder(undefined)).toEqual(['http', 'sse'])
  })

  it('does not re-probe a known transport', () => {
    // Persisting the transport is pointless if we probe anyway; these two cases
    // are the entire payoff of storing it.
    expect(transportOrder('sse')).toEqual(['sse'])
    expect(transportOrder('http')).toEqual(['http'])
  })

  it('never returns an empty order', () => {
    for (const known of [undefined, 'http', 'sse'] as const) {
      expect(transportOrder(known).length).toBeGreaterThan(0)
    }
  })
})
