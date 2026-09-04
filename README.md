# mcp-gateway

Hardening utilities for an MCP gateway — a server that fronts other people's MCP servers.

These are extracted from [BusinessMCP](https://businessmcp.com)'s production gateway, which lets a
workspace connect third-party MCP servers and re-expose them through one governed endpoint. Fronting
someone else's server means fetching a URL a user supplied, on your infrastructure, and that has a
small number of ways to go badly wrong. This is what we run.

MIT. No dependencies for the two core modules — two Node builtins and nothing else.

```
npm install @modelcontextprotocol/client   # only if you use the transport helper
```

---

## 1. The SSRF guard, and the bypass that survived a passing test suite

A gateway takes a URL from a user and fetches it. Without a guard that is a direct path to
`http://169.254.169.254/` and your cloud credentials.

The obvious implementation checks the host against a list of reserved ranges. Ours did, including
IPv4-mapped IPv6:

```ts
const mapped = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/)   // ← the bug
```

That regex never fired in production. The WHATWG URL parser — `new URL()`, what every caller
actually uses — normalizes IPv6 hosts to their canonical form, and the canonical form of an
IPv4-mapped address is **hex**:

```js
new URL('http://[::ffff:169.254.169.254]/').hostname
// '::ffff:a9fe:a9fe'
```

The dotted spelling the regex matched is a shape no caller can produce. The unit test passed because
it called the guard with the dotted string directly. It was green, and it was meaningless: the guard
was only ever exercised through an input the real code path could not generate.

Every one of these reached the fetch:

| URL | `URL.hostname` | Actually |
|---|---|---|
| `http://[::ffff:169.254.169.254]/` | `::ffff:a9fe:a9fe` | cloud metadata |
| `http://[::ffff:127.0.0.1]/` | `::ffff:7f00:1` | loopback |
| `http://[::127.0.0.1]/` | `::7f00:1` | loopback (IPv4-compatible) |
| `http://[64:ff9b::169.254.169.254]/` | `64:ff9b::a9fe:a9fe` | cloud metadata (NAT64) |
| `http://[2002:a9fe:a9fe::]/` | `2002:a9fe:a9fe::` | cloud metadata (6to4) |

**Adding more prefixes to the list is not the fix.** IPv6 has several mechanisms that embed an IPv4
address, and matching text means playing whack-a-mole against a normalizer you do not control. This
guard decodes the address to its eight 16-bit groups and checks numerically, unwrapping every
embedding it knows (`::ffff:` mapped, `::` compatible, `64:ff9b::` NAT64, `2002::` 6to4) and
recursing into the inner IPv4. **Undecodable input fails closed** — an address you cannot parse is
one you cannot vouch for.

```ts
import { isPublicHttpUrl, isBlockedIp } from '@businessmcp/mcp-gateway'

await isPublicHttpUrl('http://[::ffff:169.254.169.254]/')  // false
await isPublicHttpUrl('https://api.example.com/mcp')       // true, after resolving every A/AAAA
isBlockedIp('::ffff:a9fe:a9fe')                            // true
```

`isPublicHttpUrl` resolves the hostname and requires **every** returned address to be public, which
is a best-effort DNS-rebinding defence. It is not a complete one: a rebind between this check and the
socket connect is a real TOCTOU window, and closing it means pinning the resolved IP into the
connection. We accept that residual risk and think you should know about it rather than discover it.

There is a second trap this does not solve for you. Validating a host once and then calling
`fetch(url, { redirect: 'follow' })` is a bypass: the server 302s to `http://127.0.0.1/` and the
follow is never checked. **Follow redirects manually and re-validate every hop.**

## 2. Classify upstream failures — never swallow them

The version of this code that shipped first wrapped every upstream call in `catch {}` and dropped
the server from the tool list. Auth failure, unsupported transport, timeout, blocked host and
"server is fine, returned nothing" were indistinguishable — which is to say invisible. Users saw
tools silently missing, with no explanation anywhere in the product.

```ts
import { classifyUpstreamError, describeFailure } from '@businessmcp/mcp-gateway'

const failure = classifyUpstreamError(err)
// { reason: 'auth_required' | 'transport_unsupported' | 'timeout'
//         | 'blocked_host' | 'unreachable', detail: string }

describeFailure(failure)  // a sentence you can show a user
```

The reason is also what makes a retry decision honest: only a handshake-shaped failure is worth
retrying on another transport. An auth rejection fails identically either way.

## 3. Namespace tool names without collisions

Aggregating N servers means prefixing their tools. MCP caps names at 64 characters, so prefixing
plus truncation can map two different upstream tools to the same string — and then a lookup by name
dispatches the call to **the wrong server**.

```ts
import { namespacedToolName } from '@businessmcp/mcp-gateway'

namespacedToolName('stripe', 'create_payment_intent')
// 'ext_stripe_create_payment_intent'
```

When truncation is needed a short hash of the full name is appended, so two long names stay distinct.

## 4. Transport fallback

MCP's 2026-07-28 revision dropped legacy HTTP+SSE for *servers*, but plenty of servers you connect
*to* still only speak it. `withUpstream` tries streamable HTTP, falls back to SSE, and tells you
which worked so you can persist it and skip the probe next time.

```ts
import { withUpstream } from '@businessmcp/mcp-gateway'

const res = await withUpstream(
  { url, headers, transport: knownTransport },
  (client) => client.listTools(),
  { onTransportResolved: (t) => save(t) },
)
if (!res.ok) log(describeFailure(res.failure))
```

Requires `@modelcontextprotocol/client` as a peer dependency. The other modules do not.

---

## Honest limits

- **Utilities, not a framework.** There is no gateway here — no aggregation, no auth, no policy
  layer. Those are meaningfully coupled to how you store connections, and a fake abstraction over
  that would be worse than none.
- **No external audit.** This is what we run in production. That is a reason to take it seriously and
  not a substitute for review.
- **The aggregation and inspection layers are deliberately not included**, partly because they are
  coupled to our database and partly because they have no test coverage. Everything shipped here is
  from the tested side.
- **DNS-rebinding TOCTOU is open**, as described above.

## Development

This package is **generated** from the BusinessMCP monorepo, where these modules are in active
production use. Fixes should go there and be regenerated — a patch applied only here would be
overwritten, and two hand-maintained copies of a security guard is the exact failure that produced
the bypass in section 1.

Issues and reports are welcome here regardless.

```sh
npm install
npx vitest run
npx tsc --noEmit
```
