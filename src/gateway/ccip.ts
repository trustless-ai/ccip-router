import { Hono } from 'hono'

// EIP-3668 CCIP-Read gateway handler
// Decodes sender + calldata, routes to handler, returns ABI-encoded response
export const ccipRouter = new Hono()

ccipRouter.get('/:sender/:data.json', async (c) => {
  const sender = c.req.param('sender')
  const data = c.req.param('data')

  // TODO: decode calldata, route to resolver logic, sign response
  return c.json({ sender, data }, 200)
})
