import { afterEach, describe, expect, it, vi } from 'vitest'
import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { CloudflareAccessVerifier } from '../src/cloudflare-access.ts'

const TEAM_DOMAIN = 'https://example.cloudflareaccess.com'
const AUDIENCE = 'test-application-audience'

async function fixture() {
  const { privateKey, publicKey } = await generateKeyPair('RS256')
  const jwk = await exportJWK(publicKey)
  jwk.kid = 'test-key'
  jwk.alg = 'RS256'
  jwk.use = 'sig'
  vi.stubGlobal('fetch', vi.fn(async () => new Response(
    JSON.stringify({ keys: [jwk] }),
    { status: 200, headers: { 'content-type': 'application/json' } },
  )))
  const verifier = CloudflareAccessVerifier.create({
    teamDomain: TEAM_DOMAIN,
    audience: AUDIENCE,
  })!
  const token = async (overrides: { issuer?: string; audience?: string; expired?: boolean } = {}) => {
    const now = Math.floor(Date.now() / 1000)
    return new SignJWT({ sub: 'user-id' })
      .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
      .setIssuer(overrides.issuer ?? TEAM_DOMAIN)
      .setAudience(overrides.audience ?? AUDIENCE)
      .setIssuedAt(now)
      .setNotBefore(now - 1)
      .setExpirationTime(overrides.expired === true ? now - 1 : now + 300)
      .sign(privateKey)
  }
  return { verifier, token }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('CloudflareAccessVerifier', () => {
  it('validates a signed Access JWT with the configured issuer and audience', async () => {
    const { verifier, token } = await fixture()
    expect(await verifier.verify({ 'cf-access-jwt-assertion': await token() })).toBe(true)
  })

  it('rejects missing, malformed, expired, wrong-issuer, and wrong-audience tokens', async () => {
    const { verifier, token } = await fixture()
    expect(await verifier.verify({})).toBe(false)
    expect(await verifier.verify({ 'cf-access-jwt-assertion': 'not-a-jwt' })).toBe(false)
    expect(await verifier.verify({ 'cf-access-jwt-assertion': await token({ expired: true }) })).toBe(false)
    expect(await verifier.verify({ 'cf-access-jwt-assertion': await token({ issuer: 'https://other.cloudflareaccess.com' }) })).toBe(false)
    expect(await verifier.verify({ 'cf-access-jwt-assertion': await token({ audience: 'other-audience' }) })).toBe(false)
  })

  it('requires an HTTPS origin team domain', () => {
    expect(() => CloudflareAccessVerifier.create({
      teamDomain: 'http://example.cloudflareaccess.com',
      audience: AUDIENCE,
    })).toThrow('teamDomain')
  })
})
