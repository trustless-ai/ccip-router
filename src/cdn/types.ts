export interface CdnProvider {
  readonly name: string
  upload(content: Buffer, filename: string, mimeType: string): Promise<string> // returns CID
}
