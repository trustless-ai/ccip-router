export const ATTESTATION_INDEX_ABI = [
  {
    type: 'function',
    name: 'record',
    inputs: [
      {
        name: 'a', type: 'tuple',
        components: [
          { name: 'agentId',                  type: 'bytes32' },
          { name: 'registry',                 type: 'address' },
          { name: 'modelHash',                type: 'bytes32' },
          { name: 'rawInputHash',             type: 'bytes32' },
          { name: 'sanitizationPipelineHash', type: 'bytes32' },
          { name: 'inputHash',                type: 'bytes32' },
          { name: 'outputHash',               type: 'bytes32' },
          { name: 'commitmentHash',           type: 'bytes32' },
          { name: 'timestamp',                type: 'uint256' },
        ],
      },
      { name: 'signature', type: 'bytes' },
    ],
    outputs: [{ name: 'signer', type: 'address' }],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function',
    name: 'isRecorded',
    inputs:  [{ name: 'commitmentHash', type: 'bytes32' }],
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'signerOf',
    inputs:  [{ name: 'commitmentHash', type: 'bytes32' }],
    outputs: [{ name: '', type: 'address' }],
    stateMutability: 'view',
  },
  {
    type: 'function',
    name: 'commitmentOf',
    inputs:  [{ name: 'inputHash', type: 'bytes32' }],
    outputs: [{ name: '', type: 'bytes32' }],
    stateMutability: 'view',
  },
  {
    type: 'event',
    name: 'AttestationRecorded',
    inputs: [
      { name: 'commitmentHash', type: 'bytes32', indexed: true },
      { name: 'inputHash',      type: 'bytes32', indexed: true },
      { name: 'agentId',        type: 'bytes32', indexed: true },
      { name: 'signer',         type: 'address', indexed: false },
      { name: 'timestamp',      type: 'uint256', indexed: false },
    ],
  },
] as const

export const WYRIWE_ATTESTATION_VERIFIER_ABI = [
  {
    type: 'function',
    name: 'verify',
    inputs: [
      { name: 'attestationHash', type: 'bytes32' },
      { name: 'proof',           type: 'bytes' },
    ],
    outputs: [{ name: '', type: 'bool' }],
    stateMutability: 'view',
  },
] as const

export const NODE_REGISTRY_ABI = [
  {
    type: 'function', name: 'register',
    inputs:  [{ name: 'url', type: 'string' }, { name: 'signature', type: 'bytes' }],
    outputs: [{ name: 'signer', type: 'address' }],
    stateMutability: 'nonpayable',
  },
  {
    type: 'function', name: 'getNode',
    inputs:  [{ name: 'signer', type: 'address' }],
    outputs: [{ name: 'url', type: 'string' }, { name: 'registeredAt', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function', name: 'nodeCount',
    inputs: [], outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    type: 'function', name: 'getNodes',
    inputs:  [{ name: 'offset', type: 'uint256' }, { name: 'limit', type: 'uint256' }],
    outputs: [
      { name: 'signers',    type: 'address[]' },
      { name: 'urls',       type: 'string[]' },
      { name: 'timestamps', type: 'uint256[]' },
    ],
    stateMutability: 'view',
  },
  {
    type: 'event', name: 'NodeRegistered',
    inputs: [
      { name: 'signer', type: 'address', indexed: true },
      { name: 'url',    type: 'string',  indexed: false },
    ],
  },
] as const
