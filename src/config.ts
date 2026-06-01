export type Config = {
  port: number
  dbPath: string
  gatewayKey: `0x${string}` | null  // null = dry-run, no signing
  peers: string[]
  syncInterval: string              // cron expression
  syncNamespace: string
}

function requireHex(key: string, val: string | undefined): `0x${string}` {
  if (!val) throw new Error(`${key} is required`)
  if (!val.startsWith('0x') || val.length < 4) throw new Error(`${key} must be a hex string starting with 0x`)
  return val as `0x${string}`
}

function parsePeers(val: string | undefined): string[] {
  if (!val || val.trim() === '') return []
  return val
    .split(',')
    .map((u) => u.trim())
    .filter(Boolean)
    .map((u) => {
      try { new URL(u) } catch { throw new Error(`Invalid peer URL: "${u}"`) }
      return u.replace(/\/$/, '') // strip trailing slash
    })
}

function parsePort(val: string | undefined): number {
  const n = Number(val ?? 3000)
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error(`PORT must be 1–65535, got "${val}"`)
  return n
}

export function loadConfig(): Config {
  const raw = {
    PORT:                process.env.PORT,
    DB_PATH:             process.env.DB_PATH,
    GATEWAY_PRIVATE_KEY: process.env.GATEWAY_PRIVATE_KEY,
    PEERS:               process.env.PEERS,
    SYNC_INTERVAL:       process.env.SYNC_INTERVAL,
    SYNC_NAMESPACE:      process.env.SYNC_NAMESPACE,
  }

  const gatewayKey = raw.GATEWAY_PRIVATE_KEY
    ? requireHex('GATEWAY_PRIVATE_KEY', raw.GATEWAY_PRIVATE_KEY)
    : null

  if (!gatewayKey) {
    console.warn('[config] GATEWAY_PRIVATE_KEY not set — running in dry-run mode (no signing)')
  }

  const peers = parsePeers(raw.PEERS)

  return {
    port:          parsePort(raw.PORT),
    dbPath:        raw.DB_PATH ?? './data.db',
    gatewayKey,
    peers,
    syncInterval:  raw.SYNC_INTERVAL ?? '*/5 * * * *',
    syncNamespace: raw.SYNC_NAMESPACE ?? 'agent-attestations',
  }
}

// Singleton — parsed once at startup, imported everywhere
let _config: Config | null = null

export function getConfig(): Config {
  if (!_config) _config = loadConfig()
  return _config
}
