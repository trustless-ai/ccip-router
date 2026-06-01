// Public library surface — import from 'ccip-router' in downstream projects
export { CcipRouter } from './router/index.js'
export type { ResolverFn, CcipRouterOptions, IdentityOpts } from './router/CcipRouter.js'
export { withWyriwe } from './attestation/withWyriwe.js'
export type { WyriweOpts } from './attestation/withWyriwe.js'
export type { DB, MeshRecord, PeerState } from './db/types.js'
