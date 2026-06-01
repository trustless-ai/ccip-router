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
