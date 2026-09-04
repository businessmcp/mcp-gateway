import { Client } from '@modelcontextprotocol/client'
import { SSEClientTransport, StreamableHTTPClientTransport } from '@modelcontextprotocol/client'
import { classifyUpstreamError, transportOrder, type UpstreamFailure, type UpstreamTransport } from './upstream-logic'

export type UpstreamTarget = {
  url: string
  /** Sent verbatim to a third party. Validate before you get here. */
  headers?: Record<string, string>
  /** Last known working transport. Persist it and pass it back to skip the probe. */
  transport?: UpstreamTransport
}

export type UpstreamResult<T> = { ok: true; value: T } | { ok: false; failure: UpstreamFailure }

export type WithUpstreamOptions = {
  connectTimeoutMs?: number
  clientName?: string
  clientVersion?: string
  /** Called when the working transport differs from the one passed in. */
  onTransportResolved?: (transport: UpstreamTransport) => void
}

const DEFAULT_CONNECT_TIMEOUT_MS = 8000

/**
 * Connect to an upstream MCP server and run `fn`, trying streamable HTTP and
 * falling back to the legacy HTTP+SSE transport.
 *
 * Only a handshake-shaped failure is retried on the other transport: an auth
 * rejection or a blocked host fails identically either way, so retrying it just
 * doubles the latency of a request that was never going to work.
 */
export async function withUpstream<T>(
  target: UpstreamTarget,
  fn: (client: Client) => Promise<T>,
  options: WithUpstreamOptions = {},
): Promise<UpstreamResult<T>> {
  const {
    connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS,
    clientName = 'mcp-gateway',
    clientVersion = '0.1.0',
    onTransportResolved,
  } = options

  let last: UpstreamFailure = { reason: 'unreachable', detail: 'no transport attempted' }

  for (const transport of transportOrder(target.transport)) {
    const url = new URL(target.url)
    const requestInit = target.headers ? { headers: target.headers } : undefined
    const client = new Client({ name: clientName, version: clientVersion }, { capabilities: {} })
    try {
      const t =
        transport === 'http'
          ? new StreamableHTTPClientTransport(url, { requestInit })
          : new SSEClientTransport(url, { requestInit })
      await client.connect(t, { timeout: connectTimeoutMs })
      const value = await fn(client)
      if (target.transport !== transport) onTransportResolved?.(transport)
      return { ok: true, value }
    } catch (err) {
      last = classifyUpstreamError(err)
      if (last.reason !== 'transport_unsupported' && last.reason !== 'unreachable') break
    } finally {
      try {
        await client.close()
      } catch {
        /* a failed close must not mask the original error */
      }
    }
  }
  return { ok: false, failure: last }
}
