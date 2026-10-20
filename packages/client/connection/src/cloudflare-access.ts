/** Cloudflare Access JWT verification for browser-session bootstrap. */

import { createRemoteJWKSet, jwtVerify } from 'jose'
import type { ConnectionTrustRequest } from './rpc.ts'

/** Cloudflare Access bootstrap configuration for the browser session. */
export interface CloudflareAccessConfig {
  /** Cloudflare Access team origin (HTTPS) whose `/cdn-cgi/access/certs` JWKS signs the tokens. */
  readonly teamDomain: string
  /** Expected JWT `aud` claim of issued Access tokens. */
  readonly audience: string
}

function header(
  headers: ConnectionTrustRequest['headers'],
  name: string,
): string | undefined {
  const wanted = name.toLowerCase()
  if (headers instanceof Headers) return headers.get(wanted) ?? undefined
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() !== wanted || typeof value !== 'string') continue
    return value
  }
  return undefined
}

function canonicalTeamDomain(value: string): string {
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    throw new Error('client-connection: Cloudflare Access teamDomain must be an HTTPS URL')
  }
  if (parsed.protocol !== 'https:' || parsed.username !== '' || parsed.password !== ''
    || parsed.pathname !== '/' || parsed.search !== '' || parsed.hash !== '') {
    throw new Error('client-connection: Cloudflare Access teamDomain must be an HTTPS origin')
  }
  return parsed.origin
}

/** Verifies Access tokens without logging token contents or identity claims. */
export class CloudflareAccessVerifier {
  private readonly jwks

  private constructor(
    private readonly teamDomain: string,
    private readonly audience: string,
  ) {
    this.jwks = createRemoteJWKSet(
      new URL(`${teamDomain}/cdn-cgi/access/certs`),
    )
  }

  /**
   * Build a verifier from the connection configuration.
   * @param config - Access team domain and expected audience, or undefined to disable verification.
   * @returns a verifier, or undefined when Access is not configured.
   */
  static create(config: CloudflareAccessConfig | undefined): CloudflareAccessVerifier | undefined {
    if (config === undefined) return undefined
    if (config.audience.trim() === '') {
      throw new Error('client-connection: Cloudflare Access audience must not be empty')
    }
    return new CloudflareAccessVerifier(canonicalTeamDomain(config.teamDomain), config.audience)
  }

  /**
   * Verify the request's `cf-access-jwt-assertion` header against the team JWKS.
   * @param headers - request headers carrying the Access JWT assertion.
   * @returns true when the assertion verifies, false for absent, oversized, or invalid tokens.
   */
  async verify(headers: ConnectionTrustRequest['headers']): Promise<boolean> {
    const token = header(headers, 'cf-access-jwt-assertion')
    if (token === undefined || token.length > 16 * 1024) return false
    try {
      await jwtVerify(token, this.jwks, {
        issuer: this.teamDomain,
        audience: this.audience,
        algorithms: ['RS256'],
        requiredClaims: ['exp', 'nbf'],
      })
      return true
    } catch {
      return false
    }
  }
}
