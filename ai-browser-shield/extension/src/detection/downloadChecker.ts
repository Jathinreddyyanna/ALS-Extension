const HIGH_RISK_EXTENSIONS = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.vbs', '.js', '.jar', '.msi', '.ps1', '.hta', '.wsf', '.com', '.reg']
const MEDIUM_RISK_EXTENSIONS = ['.zip', '.rar', '.7z', '.dmg', '.pkg', '.deb', '.apk', '.iso']

export interface DownloadRisk {
  level: 'safe' | 'medium' | 'high'
  reason: string
}

export function checkDownload(filename: string, mimeType: string, sourceUrl: string): DownloadRisk {
  const ext = ('.' + filename.split('.').pop()?.toLowerCase()) || ''
  const lowerName = filename.toLowerCase()
  const lowerUrl = sourceUrl.toLowerCase()
  const doubleExtensionRe = /\.(pdf|doc|docx|xls|xlsx|jpg|jpeg|png|txt)\.(exe|scr|js|vbs|bat|cmd|msi|ps1)$/i

  if (HIGH_RISK_EXTENSIONS.includes(ext)) {
    return { level: 'high', reason: `Executable file type (${ext}) can run code on your computer` }
  }

  if (doubleExtensionRe.test(lowerName)) {
    return { level: 'high', reason: 'File uses a deceptive double extension to disguise executable content' }
  }

  if (HIGH_RISK_EXTENSIONS.some((highRiskExt) => lowerUrl.includes(highRiskExt))) {
    return { level: 'high', reason: 'Download URL points directly to a risky executable file' }
  }

  const mimeRisk = mimeType.includes('application/x-') || mimeType.includes('application/octet-stream')
  if (mimeRisk && !MEDIUM_RISK_EXTENSIONS.includes(ext)) {
    return { level: 'high', reason: 'File MIME type indicates executable or unknown binary content' }
  }

  if (MEDIUM_RISK_EXTENSIONS.includes(ext)) {
    return { level: 'medium', reason: `Archive file (${ext}) may contain hidden executables` }
  }

  try {
    const url = new URL(sourceUrl)
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(url.hostname)) {
      return { level: 'medium', reason: 'File is being downloaded from an IP address, not a domain name' }
    }
    if (url.protocol === 'http:' && !MEDIUM_RISK_EXTENSIONS.includes(ext)) {
      return { level: 'medium', reason: 'File is being downloaded over insecure HTTP' }
    }
  } catch {}

  return { level: 'safe', reason: 'No obvious threats detected' }
}
