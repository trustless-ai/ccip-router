import type { CdnProvider } from './types.js'

export class PinataProvider implements CdnProvider {
  readonly name = 'pinata'

  constructor(private readonly jwt: string) {}

  async upload(content: Buffer, filename: string, mimeType: string): Promise<string> {
    const form = new FormData()
    form.append('file', new Blob([content.buffer as ArrayBuffer], { type: mimeType }), filename)
    const res = await fetch('https://api.pinata.cloud/pinning/pinFileToIPFS', {
      method: 'POST',
      headers: { Authorization: `Bearer ${this.jwt}` },
      body: form,
    })
    if (!res.ok) throw new Error(`Pinata: ${res.status} ${await res.text()}`)
    const data = await res.json() as { IpfsHash: string }
    return data.IpfsHash
  }
}
