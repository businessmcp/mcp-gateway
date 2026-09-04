import { describe, expect, it } from 'vitest'
import { isBlockedIp, isPublicHttpUrl } from './ssrf'

// This is the guard standing between a workspace-supplied URL and our server's
// network position, and it was previously untested.

describe('isBlockedIp', () => {
  it('blocks the cloud metadata address', () => {
    expect(isBlockedIp('169.254.169.254')).toBe(true)
  })

  it.each([
    ['0.0.0.0', 'this-host'],
    ['127.0.0.1', 'loopback'],
    ['10.1.2.3', 'private /8'],
    ['172.16.0.1', 'private /12 lower bound'],
    ['172.31.255.255', 'private /12 upper bound'],
    ['192.168.1.1', 'private /16'],
    ['100.64.0.1', 'CGNAT'],
    ['224.0.0.1', 'multicast'],
    ['255.255.255.255', 'reserved'],
  ])('blocks %s (%s)', (ip) => {
    expect(isBlockedIp(ip)).toBe(true)
  })

  it.each([
    ['8.8.8.8'],
    ['1.1.1.1'],
    ['172.15.0.1'], // just below the private /12
    ['172.32.0.1'], // just above the private /12
    ['100.63.0.1'], // just below CGNAT
    ['100.128.0.1'], // just above CGNAT
    ['223.255.255.255'], // just below multicast
  ])('allows public %s', (ip) => {
    expect(isBlockedIp(ip)).toBe(false)
  })

  it('blocks IPv6 loopback, link-local, ULA and multicast', () => {
    for (const ip of ['::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1']) {
      expect(isBlockedIp(ip), ip).toBe(true)
    }
  })

  it('sees through IPv4-mapped IPv6, which would otherwise smuggle a private address', () => {
    expect(isBlockedIp('::ffff:127.0.0.1')).toBe(true)
    expect(isBlockedIp('::ffff:169.254.169.254')).toBe(true)
    expect(isBlockedIp('::ffff:8.8.8.8')).toBe(false)
  })

  it('is case-insensitive', () => {
    expect(isBlockedIp('FE80::1')).toBe(true)
  })
})

describe('isPublicHttpUrl', () => {
  it('rejects non-http(s) schemes', async () => {
    for (const u of ['file:///etc/passwd', 'gopher://x/', 'ftp://x/', 'javascript:alert(1)']) {
      expect(await isPublicHttpUrl(u), u).toBe(false)
    }
  })

  it('rejects unparseable input', async () => {
    expect(await isPublicHttpUrl('not a url')).toBe(false)
    expect(await isPublicHttpUrl('')).toBe(false)
  })

  it('rejects localhost by name and the GCP metadata hostname', async () => {
    for (const u of [
      'http://localhost/',
      'http://localhost:3000/mcp',
      'http://foo.localhost/',
      'http://metadata.google.internal/',
    ]) {
      expect(await isPublicHttpUrl(u), u).toBe(false)
    }
  })

  it('rejects reserved IP literals without needing DNS', async () => {
    for (const u of [
      'http://127.0.0.1/mcp',
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.5/',
      'http://[::1]/',
      'http://[fe80::1]/',
    ]) {
      expect(await isPublicHttpUrl(u), u).toBe(false)
    }
  })

  it('allows a public IP literal', async () => {
    expect(await isPublicHttpUrl('https://8.8.8.8/mcp')).toBe(true)
  })

  // Regression: the guard used to string-match `::ffff:127.0.0.1`, the DOTTED
  // spelling. The WHATWG URL parser normalizes that host to `::ffff:7f00:1` in
  // HEX, so the match never fired on a real URL and every one of these reached
  // the fetch. The unit test passed the dotted form directly, which is a shape
  // no caller ever produces. isBlockedIp now decodes the address instead.
  it.each([
    ['IPv4-mapped loopback', 'http://[::ffff:127.0.0.1]/'],
    ['IPv4-mapped cloud metadata', 'http://[::ffff:169.254.169.254]/latest/meta-data/'],
    ['IPv4-mapped, fully expanded', 'http://[0:0:0:0:0:ffff:127.0.0.1]/'],
    ['IPv4-mapped private', 'http://[::ffff:10.0.0.1]/'],
    ['IPv4-compatible (deprecated)', 'http://[::127.0.0.1]/'],
    ['NAT64 64:ff9b::/96', 'http://[64:ff9b::169.254.169.254]/'],
    ['6to4 2002::/16', 'http://[2002:a9fe:a9fe::]/'],
  ])('blocks %s', async (_label, url) => {
    expect(await isPublicHttpUrl(url)).toBe(false)
  })

  it('still allows a genuinely public IPv6 host', async () => {
    expect(await isPublicHttpUrl('https://[2606:4700:4700::1111]/')).toBe(true)
    expect(await isPublicHttpUrl('https://[::ffff:8.8.8.8]/')).toBe(true)
  })

  it('fails closed on an undecodable address', () => {
    // An address we cannot decode is one we cannot vouch for.
    expect(isBlockedIp('not-an-address')).toBe(true)
    expect(isBlockedIp('1:2:3')).toBe(true)
  })
})
