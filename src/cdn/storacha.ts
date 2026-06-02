import type { CdnProvider } from './types.js'

export class StorachaProvider implements CdnProvider {
  readonly name = 'storacha'

  constructor(private readonly token: string) {}

  async upload(content: Buffer, filename: string, mimeType: string): Promise<string> {
    const form = new FormData()
    form.append('file', new Blob([content.buffer as ArrayBuffer], { type: mimeType }), filename)
    const res = await fetch('https://api.web3.storage/upload', {
      method: 'POST',
      headers: { Authorization: `Bearer ${this.token}` },
      body: form,
    })
    if (!res.ok) throw new Error(`Web3.Storage: ${res.status} ${await res.text()}`)
    const data = await res.json() as { cid: string }
    return data.cid
  }
}
