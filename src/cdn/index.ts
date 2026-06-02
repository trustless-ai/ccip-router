import type { Config } from '../config.js'
import type { CdnProvider } from './types.js'
import { PinataProvider } from './pinata.js'
import { StorachaProvider } from './storacha.js'

export type { CdnProvider }

export function getCdnProvider(config: Config): CdnProvider | null {
  if (!config.cdnProvider || !config.cdnApiKey) return null
  switch (config.cdnProvider) {
    case 'pinata':   return new PinataProvider(config.cdnApiKey)
    case 'storacha': return new StorachaProvider(config.cdnApiKey)
    default:         return null
  }
}
