import cron from 'node-cron'
import type { DB } from '../db/types.js'
import type { Config } from '../config.js'
import { syncPeer } from './sync.js'

export function startSyncCron(config: Config, db: DB): void {
  if (!cron.validate(config.syncInterval)) {
    throw new Error(`[cron] invalid SYNC_INTERVAL: "${config.syncInterval}"`)
  }

  if (config.peers.length === 0 && !config.autoDiscover) {
    console.log('[cron] no peers configured and auto-discover off — sync cron not started')
    return
  }

  console.log(`[cron] sync starting — interval: ${config.syncInterval}, namespace: ${config.syncNamespace}`)

  cron.schedule(config.syncInterval, async () => {
    const peers = await db.getPeers()
    if (!peers.length) return

    await Promise.allSettled(
      peers.map(async (peer) => {
        const update = await syncPeer(peer, config.syncNamespace, db, config.autoDiscover, config.nodeUrl ?? undefined)
        await db.upsertPeer({ ...peer, ...update })
      }),
    )
  })
}
