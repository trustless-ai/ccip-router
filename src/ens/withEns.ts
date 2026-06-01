import { decodeAbiParameters, encodeAbiParameters, hexToBytes } from 'viem'
import type { ResolverFn } from '../router/index.js'
import { decodeDnsName } from './dns.js'

// ENS record types passed to the clean resolver function
export type EnsRecord =
  | { type: 'addr' }
  | { type: 'addr'; coinType: bigint }
  | { type: 'text'; key: string }
  | { type: 'contenthash' }

// Clean resolver interface — return the value, withEns handles ABI encoding
// addr        → ethereum address string "0x..."
// addr+coin   → coin-specific bytes "0x..." (already encoded for the coin type)
// text        → plain string value
// contenthash → hex bytes "0x..."
// Return null for not found — withEns returns the zero value for the record type
export type EnsResolverFn = (
  name:   string,
  record: EnsRecord,
) => Promise<string | null>

const RESOLVE_SELECTOR = '0x9061b923' // resolve(bytes,bytes)
const ADDR_SELECTOR    = '0x3b3b57de' // addr(bytes32)
const ADDR_CT_SELECTOR = '0xf1cb7e06' // addr(bytes32,uint256)
const TEXT_SELECTOR    = '0x59d1d43c' // text(bytes32,string)
const CONTENTHASH_SEL  = '0xbc1c58d1' // contenthash(bytes32)

// Wrap any EnsResolverFn as a ResolverFn for use with CcipRouter.
//
// Decodes the ENS resolve(bytes name, bytes data) calldata, dispatches to
// the clean resolver with a typed EnsRecord, and ABI-encodes the response.
//
// Composes with withWyriwe — put withEns inside:
//   resolver = withWyriwe(withEns(myEnsResolver), wyriweOpts)
export function withEns(resolver: EnsResolverFn): ResolverFn {
  return async (sender, calldata, namespace) => {
    if (!calldata.toLowerCase().startsWith(RESOLVE_SELECTOR)) {
      throw new Error(`[withEns] unexpected selector: ${calldata.slice(0, 10)}`)
    }

    // Decode outer resolve(bytes name, bytes data)
    const [nameBytes, innerData] = decodeAbiParameters(
      [{ type: 'bytes' }, { type: 'bytes' }],
      `0x${calldata.slice(10)}` as `0x${string}`,
    )

    // DNS wire-format → "vitalik.eth"
    const name     = decodeDnsName(hexToBytes(nameBytes))
    const selector = (innerData as string).slice(0, 10).toLowerCase()
    const inner    = `0x${(innerData as string).slice(10)}` as `0x${string}`

    switch (selector) {
      case ADDR_SELECTOR: {
        // addr(bytes32) → address
        const result = await resolver(name, { type: 'addr' })
        const addr   = (result ?? '0x0000000000000000000000000000000000000000') as `0x${string}`
        return encodeAbiParameters([{ type: 'address' }], [addr])
      }

      case ADDR_CT_SELECTOR: {
        // addr(bytes32,uint256) → bytes (coin-type specific encoding)
        const [, coinType] = decodeAbiParameters(
          [{ type: 'bytes32' }, { type: 'uint256' }],
          inner,
        )
        const result = await resolver(name, { type: 'addr', coinType: coinType as bigint })
        return encodeAbiParameters([{ type: 'bytes' }], [(result ?? '0x') as `0x${string}`])
      }

      case TEXT_SELECTOR: {
        // text(bytes32,string) → string
        const [, key] = decodeAbiParameters(
          [{ type: 'bytes32' }, { type: 'string' }],
          inner,
        )
        const result = await resolver(name, { type: 'text', key: key as string })
        return encodeAbiParameters([{ type: 'string' }], [result ?? ''])
      }

      case CONTENTHASH_SEL: {
        // contenthash(bytes32) → bytes
        const result = await resolver(name, { type: 'contenthash' })
        return encodeAbiParameters([{ type: 'bytes' }], [(result ?? '0x') as `0x${string}`])
      }

      default:
        return '0x'
    }
  }
}
