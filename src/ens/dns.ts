// DNS wire-format name decoder (RFC 1035)
// Converts a DNS-encoded name byte array to a dot-separated string.
// e.g. 0x 07 vitalik 03 eth 00 → "vitalik.eth"
export function decodeDnsName(bytes: Uint8Array): string {
  const labels: string[] = []
  let i = 0
  while (i < bytes.length && bytes[i] !== 0) {
    const len = bytes[i]
    i++
    labels.push(new TextDecoder().decode(bytes.slice(i, i + len)))
    i += len
  }
  return labels.join('.')
}

// Encode a dot-separated name to DNS wire format
export function encodeDnsName(name: string): Uint8Array {
  const labels  = name.split('.')
  const parts: number[] = []
  for (const label of labels) {
    parts.push(label.length)
    for (const char of label) parts.push(char.charCodeAt(0))
  }
  parts.push(0)
  return new Uint8Array(parts)
}
