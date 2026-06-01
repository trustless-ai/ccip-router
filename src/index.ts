import { Hono } from 'hono'
import { CcipRouter } from './router/index.js'
import { withWyriwe } from './attestation/withWyriwe.js'
import { recordsRouter } from './mesh/records.js'
import { verifyRouter } from './verify/verify.js'

// ---------------------------------------------------------------------------
// Basic usage — plug in any resolver, no attestation required
// ---------------------------------------------------------------------------
// const ccip = new CcipRouter({
//   namespace: 'token-metadata',
//   resolver: async (sender, calldata, namespace) => {
//     return encodeMyResponse(calldata)
//   },
// })

// ---------------------------------------------------------------------------
// Advanced usage — wrap resolver with WYRIWE attestation (agent stack)
// ---------------------------------------------------------------------------
// const ccip = new CcipRouter({
//   namespace: 'agent-attestations',
//   resolver: withWyriwe(myAgentResolver, {
//     gatewayKey:      process.env.GATEWAY_PRIVATE_KEY as `0x${string}`,
//     registryAddress: process.env.REGISTRY_ADDRESS as `0x${string}`,
//     agentId:         process.env.AGENT_ID as `0x${string}`,
//     modelHash:       process.env.MODEL_HASH as `0x${string}`,
//   }),
// })

// ---------------------------------------------------------------------------
// Default dev resolver — returns empty bytes, useful for testing mesh sync
// ---------------------------------------------------------------------------
const ccip = new CcipRouter({
  namespace: process.env.SYNC_NAMESPACE ?? 'default',
  resolver: async (_sender, _calldata, _namespace) => {
    // replace with your resolver logic
    return '0x'
  },
})

const app = new Hono()

app.route('/', ccip.hono())
app.route('/records', recordsRouter)
app.route('/verify', verifyRouter)

app.get('/health', (c) => c.json({ ok: true, version: '0.1.0' }))

const port = Number(process.env.PORT ?? 3000)
console.log(`ccip-router listening on :${port}`)

export default { port, fetch: app.fetch }
