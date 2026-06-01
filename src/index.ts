import { Hono } from 'hono'
import { recordsRouter } from './mesh/records.js'
import { verifyRouter } from './verify/verify.js'
import { ccipRouter } from './gateway/ccip.js'

const app = new Hono()

// CCIP-Read gateway — EIP-3668
app.route('/', ccipRouter)

// Mesh sync — GET /records?since=&namespace=
app.route('/records', recordsRouter)

// Verify — GET /verify/:inputHash
app.route('/verify', verifyRouter)

const port = Number(process.env.PORT ?? 3000)
console.log(`ccip-router listening on :${port}`)

export default { port, fetch: app.fetch }
