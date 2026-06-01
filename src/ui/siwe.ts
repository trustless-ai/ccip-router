import { randomBytes } from 'node:crypto'
import { verifyMessage } from 'viem'

const NONCE_TTL_MS   = 10 * 60 * 1000        // 10 min
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000  // 7 days

// In-memory stores — cleared on restart (acceptable for a personal admin tool)
const nonces   = new Map<string, number>()                                    // nonce → expiresAt
const sessions = new Map<string, { address: `0x${string}`; expires: number }>()

export function generateNonce(): string {
  const now = Date.now()
  for (const [k, v] of nonces) if (v < now) nonces.delete(k)
  const nonce = randomBytes(16).toString('hex')
  nonces.set(nonce, now + NONCE_TTL_MS)
  return nonce
}

export function buildSiweMessage(opts: {
  domain:    string
  address:   string
  uri:       string
  chainId:   number
  nonce:     string
}): string {
  const now = new Date()
  const exp = new Date(now.getTime() + NONCE_TTL_MS)
  return [
    `${opts.domain} wants you to sign in with your Ethereum account:`,
    opts.address,
    '',
    'Sign in to ccip-router admin dashboard',
    '',
    `URI: ${opts.uri}`,
    `Version: 1`,
    `Chain ID: ${opts.chainId}`,
    `Nonce: ${opts.nonce}`,
    `Issued At: ${now.toISOString()}`,
    `Expiration Time: ${exp.toISOString()}`,
  ].join('\n')
}

export async function verifySiwe(
  message:         string,
  signature:       `0x${string}`,
  expectedAddress: `0x${string}`,
): Promise<boolean> {
  const nonceMatch = message.match(/^Nonce: (.+)$/m)
  if (!nonceMatch) return false
  const nonce = nonceMatch[1].trim()

  const expiresAt = nonces.get(nonce)
  if (!expiresAt || expiresAt < Date.now()) return false
  nonces.delete(nonce)  // one-use

  try {
    return await verifyMessage({ address: expectedAddress, message, signature })
  } catch {
    return false
  }
}

export function createSession(address: `0x${string}`): string {
  const token = randomBytes(32).toString('hex')
  sessions.set(token, { address, expires: Date.now() + SESSION_TTL_MS })
  return token
}

export function getSession(token: string): `0x${string}` | null {
  const s = sessions.get(token)
  if (!s) return null
  if (s.expires < Date.now()) { sessions.delete(token); return null }
  return s.address
}

export function deleteSession(token: string): void {
  sessions.delete(token)
}
