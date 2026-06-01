import cron from 'node-cron'
import type { DB } from '../db/types.js'
import type { Config } from '../config.js'
import { syncPeer } from './sync.js'

export function startSyncCron(config: Config, db: DB): void {
  if (config.peers.length === 0) {
    console.log('[cron] no peers configured — sync cron not started')
    return
  }

  if (!cron.validate(config.syncInterval)) {
    throw new Error(`[cron] invalid SYNC_INTERVAL: "${config.syncInterval}"`)
  }

  console.log(`[cron] sync starting — interval: ${config.syncInterval}, namespace: ${config.syncNamespace}`)

  cron.schedule(config.syncInterval, async () => {
    const peers = await db.getPeers()

    // run all peer syncs concurrently — each is independent
    await Promise.allSettled(
      peers.map(async (peer) => {
        const update = await syncPeer(peer, config.syncNamespace, db)
        await db.upsertPeer({ ...peer, ...update })
      }),
    )
  })
}
