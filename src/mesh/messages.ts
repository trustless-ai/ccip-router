import { Hono } from 'hono'
import { recoverMessageAddress } from 'viem'
import { privateKeyToAccount } from 'viem/accounts'
import { getDB } from '../db/index.js'
import { getConfig } from '../config.js'
import { NODE_VERSION } from '../version.js'
import type { MessageType } from '../db/types.js'

export const messagesRouter = new Hono()

const VALID_TYPES = new Set<MessageType>(['upgrade_notice', 'deprecation', 'network_announcement'])
const RATE_LIMIT_WINDOW = 3600  // 1 hour
const RATE_LIMIT_MAX    = 10    // max messages per peer per window

// In-memory rate limiter: signerAddress → list of receive timestamps
const rateLimits = new Map<string, number[]>()

function checkRateLimit(signer: string): boolean {
  const now  = Math.floor(Date.now() / 1000)
  const prev = (rateLimits.get(signer) ?? []).filter(t => now - t < RATE_LIMIT_WINDOW)
  if (prev.length >= RATE_LIMIT_MAX) return false
  prev.push(now)
  rateLimits.set(signer, prev)
  return true
}

// Deterministic payload string — same format used when signing
export function messagePayload(type: string, body: string, version: string, timestamp: number): string {
  return `ccip-router:message:${type}:${body}:${version}:${timestamp}`
}

// POST /messages — receive a signed message from a peer
messagesRouter.post('/', async (c) => {
  const db     = getDB()
  const config = getConfig()

  const body = await c.req.json<{
    type: string; body: string; version: string; timestamp: number; signature: string
  }>()

  const { type, body: msgBody, version, timestamp, signature } = body ?? {}

  if (!type || !msgBody || !signature || !timestamp) {
    return c.json({ error: 'type, body, timestamp, and signature required' }, 400)
  }
  if (!VALID_TYPES.has(type as MessageType)) {
    return c.json({ error: 'invalid type' }, 400)
  }

  // Recover signer
  let fromSigner: string
  try {
    fromSigner = await recoverMessageAddress({
      message:   messagePayload(type, msgBody, version ?? '', timestamp),
      signature: signature as `0x${string}`,
    })
  } catch {
    return c.json({ error: 'invalid signature' }, 400)
  }

  // Only accept from registered peers
  const peers = await db.getPeers()
  const peer  = peers.find(p => p.signerAddress?.toLowerCase() === fromSigner.toLowerCase())
  if (!peer) {
    return c.json({ error: 'unknown signer — not a registered peer' }, 403)
  }

  // Rate limit
  if (!checkRateLimit(fromSigner.toLowerCase())) {
    return c.json({ error: 'rate limit exceeded' }, 429)
  }

  // Stale message guard — reject if older than 10 minutes
  const now = Math.floor(Date.now() / 1000)
  if (Math.abs(now - timestamp) > 600) {
    return c.json({ error: 'message timestamp too old or too far in future' }, 400)
  }

  // Official flag: message signed by configured network key
  const official = !!(
    config.networkKey &&
    fromSigner.toLowerCase() === config.networkKey.toLowerCase()
  )

  await db.insertMessage({
    fromUrl:    peer.url,
    fromSigner,
    type:       type as MessageType,
    body:       msgBody,
    version:    version ?? '',
    signature,
    timestamp,
    read:       false,
    official,
  })

  console.log(`[messages] received ${type} from ${peer.url}`)
  return c.json({ ok: true })
})

// Sign and push a message to all peers — called by admin API
export async function broadcastMessage(
  type: MessageType,
  body: string,
  version = NODE_VERSION,
): Promise<{ sent: number; failed: number }> {
  const config = getConfig()
  if (!config.gatewayKey) throw new Error('GATEWAY_PRIVATE_KEY required to send messages')

  const account   = privateKeyToAccount(config.gatewayKey)
  const timestamp = Math.floor(Date.now() / 1000)
  const payload   = messagePayload(type, body, version, timestamp)
  const signature = await account.signMessage({ message: payload })

  const db    = getDB()
  const peers = await db.getPeers()
  const msg   = { type, body, version, timestamp, signature }

  let sent = 0, failed = 0
  await Promise.allSettled(
    peers.map(async (peer) => {
      try {
        const res = await fetch(new URL('/messages', peer.url).toString(), {
          method:  'POST',
          headers: { 'Content-Type': 'application/json' },
          body:    JSON.stringify(msg),
          signal:  AbortSignal.timeout(8_000),
        })
        if (res.ok) sent++
        else failed++
      } catch {
        failed++
      }
    }),
  )

  console.log(`[messages] broadcast ${type} — sent: ${sent}, failed: ${failed}`)
  return { sent, failed }
}
