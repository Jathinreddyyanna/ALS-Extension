import { describe, it, expect } from 'vitest'
import { checkDownload } from './downloadChecker'

describe('downloadChecker', () => {
  it('marks executable downloads from untrusted domains as high risk', () => {
    const risk = checkDownload('evil.exe', 'application/octet-stream', 'https://suspicious-attacker.xyz/payload.exe')
    expect(risk.level).toBe('high')
  })

  it('treats executable downloads from trusted domains as medium risk', () => {
    const risk = checkDownload('setup.exe', 'application/octet-stream', 'https://github.com/user/repo/releases/download/v1/setup.exe')
    expect(risk.level).toBe('medium')
  })

  it('treats archive files from trusted domains as safe', () => {
    const risk = checkDownload('package.zip', 'application/zip', 'https://github.com/user/repo/archive/package.zip')
    expect(risk.level).toBe('safe')
  })

  it('returns safe for benign files with no obvious threats', () => {
    const risk = checkDownload('document.pdf', 'application/pdf', 'https://example.com/document.pdf')
    expect(risk.level).toBe('safe')
  })
})

