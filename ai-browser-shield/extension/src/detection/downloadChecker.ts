const HIGH_RISK_EXTENSIONS = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.vbs', '.js', '.jar', '.msi', '.ps1', '.hta', '.wsf', '.com', '.reg']
const MEDIUM_RISK_EXTENSIONS = ['.zip', '.rar', '.7z', '.dmg', '.pkg', '.deb', '.apk', '.iso', '.tar', '.tar.gz', '.tgz']

const TRUSTED_DOMAINS = [
  'github.com',
  'raw.githubusercontent.com',
  'gitlab.com',
  'bitbucket.org',
  'google.com',
  'microsoft.com',
  'apple.com',
  'mozilla.org',
  'npmjs.com',
  'nodejs.org',
]

export interface DownloadRisk {
  level: 'safe' | 'medium' | 'high'
  reason: string
}

export interface DownloadScoreResult {
  riskScore: number
  riskLabel: 'safe' | 'suspicious' | 'dangerous'
  reason: string
}

export function checkDownload(filename: string, mimeType: string, sourceUrl: string): DownloadRisk {
  if (!filename || typeof filename !== 'string' || filename.trim() === '') {
    return { level: 'safe', reason: 'No filename provided' }
  }

  const ext = ('.' + filename.split('.').pop()?.toLowerCase()) || ''
  let hostname = ''
  try { hostname = new URL(sourceUrl).hostname } catch {}
  const isTrusted = TRUSTED_DOMAINS.some((d) => hostname === d || (hostname && hostname.endsWith(`.${d}`)))

  if (HIGH_RISK_EXTENSIONS.includes(ext)) {
    if (isTrusted) {
      return { level: 'medium', reason: `Executable file type (${ext}) from a trusted domain. Proceed only if expected.` }
    }
    return { level: 'high', reason: `Executable file type (${ext}) can run code on your computer` }
  }

  const mimeRisk = mimeType.includes('application/x-') || mimeType.includes('application/octet-stream')
  if (mimeRisk && !MEDIUM_RISK_EXTENSIONS.includes(ext)) {
    if (isTrusted) {
      return { level: 'medium', reason: 'Binary file from a trusted domain. Proceed only if expected.' }
    }
    return { level: 'high', reason: 'File MIME type indicates executable or unknown binary content' }
  }

  if (MEDIUM_RISK_EXTENSIONS.includes(ext)) {
    if (isTrusted) {
      return { level: 'safe', reason: `Archive file (${ext}) from a trusted domain. We will still scan it after download.` }
    }
    return { level: 'medium', reason: `Archive file (${ext}) may contain hidden executables` }
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    return { level: 'medium', reason: 'File is being downloaded from an IP address, not a domain name' }
  }

  return { level: 'safe', reason: 'No obvious threats detected' }
}

export function scoreDownload(filename: string, mimeType: string, sourceUrl: string): DownloadScoreResult {
  const risk = checkDownload(filename, mimeType, sourceUrl)

  if (risk.level === 'high') {
    return { riskScore: 85, riskLabel: 'dangerous', reason: risk.reason }
  }

  if (risk.level === 'medium') {
    return { riskScore: 50, riskLabel: 'suspicious', reason: risk.reason }
  }

  return { riskScore: 5, riskLabel: 'safe', reason: risk.reason }
}
