// ── Ultra-Strict Gemini Prompts — AI Browser Shield ───────────────────────────
// Every prompt is tuned to be maximally conservative and avoid false negatives.
// A missed threat is always worse than a false positive.

export function buildUrlScanPrompt(url: string, signals: Record<string, number>, riskScore: number): string {
    return `You are a strict web security assistant. Your job is to protect non-technical users from phishing, scams, and malware.
You MUST classify risk conservatively:
- If there are signs of phishing, account impersonation, or suspicious hosting, treat this as HIGH risk.
- If the URL looks like a known phishing test or demo, still treat it as HIGH risk for safety.
Do not mark clearly suspicious or test phishing URLs as LOW.

Return ONLY valid JSON — no markdown, no code fences, no extra text.

URL: ${url}
Overall Risk Score: ${riskScore}/100

Signals detected (each signal contributes to the total score):
${Object.entries(signals).map(([k, v]) => `  - ${k}: ${v} pts`).join('\n')}

Signal meanings:
- typosquatScore: Domain looks like a typo of a trusted brand (e.g. "gooogle.com")
- suspiciousTLD: Uses a known-bad top-level domain (.tk, .ml, .xyz etc)
- ipAsHostname: URL uses a raw IP address instead of a domain name
- longSubdomains: Has excessive subdomain nesting (attackers hide in subdomains)
- suspiciousKeywords: Contains phishing keywords (login, verify, secure, etc)
- encodedChars: Excessive URL encoding (used to obfuscate malicious links)
- pathEntropy: Path looks randomly generated (malware link patterns)
- portAnomaly: Using unusual/non-standard port number

Return this exact JSON (no deviations):
{
  "explanation": "2-3 sentences in plain English for a non-technical user. Explain specifically what is suspicious and why they should or shouldn't be concerned. Be specific, not generic.",
  "riskLevel": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "recommendedAction": "allow" | "warn" | "block",
  "confidence": <float 0.0 to 1.0>,
  "keyIndicators": ["up to 3 short phrases (5 words max each) describing specific red flags"]
}`;
}

export function buildFileScanPrompt(data: {
  filename: string
  extension: string
  mimeType: string
  sizeBytes: number
  sourceUrl: string
  sourceDomain: string
  domainRiskScore: number
  domainReportCount: number
  domainCategories: string[]
  contentSnippet?: string
}): string {
  const domainContext = data.domainRiskScore > 0
    ? `
Source Website Context:
  Domain: ${data.sourceDomain}
  Community Risk Score: ${data.domainRiskScore}/100
  Community Reports: ${data.domainReportCount}
  Reported For: ${data.domainCategories.join(', ') || 'not previously reported'}
  ${data.domainRiskScore >= 75 ? 'HIGH RISK SOURCE - This website is known for malware/scams' : ''}
  ${data.domainRiskScore >= 50 ? 'SUSPICIOUS SOURCE - This website has been flagged by users' : ''}
`
    : `Source Website Context:
  Domain: ${data.sourceDomain}
  Community Risk Score: 0/100 (not in our database)
`

  return `You are a malware analyst protecting a non-technical user. Analyze this download and decide if it is safe. Consider BOTH the file itself AND the website it is being downloaded from. Return ONLY valid JSON - no markdown, no code fences.

File Details:
  Name: ${data.filename}
  Extension: ${data.extension}
  MIME Type: ${data.mimeType}
  Size: ${data.sizeBytes} bytes (${(data.sizeBytes / 1024).toFixed(1)} KB)
  Source URL: ${data.sourceUrl}
  Content preview: ${data.contentSnippet || 'N/A (binary or not available)'}

${domainContext}

Analyze based on:
1. Extension vs MIME type mismatch (major red flag - e.g. .pdf that is actually .exe)
2. Executable extensions (.exe, .bat, .cmd, .ps1, .vbs, .js, .jar, .msi, .hta, .scr, .pif, .reg, .com)
3. Archive formats hiding executables (.zip, .rar, .7z, .iso, .dmg, .apk)
4. Source website reputation - if the site has HIGH risk score, even safe-looking files should be SUSPICIOUS
5. Piracy/illegal download sites are HIGH risk for malware-bundled files
6. File size anomalies (e.g. a .mp4 that is only 50KB is probably not a real video)
7. Content preview if available

Decision rules:
- If source domain risk score >= 75 -> verdict must be at least SUSPICIOUS
- If source domain risk score >= 90 -> verdict must be MALICIOUS unless file is clearly safe (PDF, image from trusted CDN)
- If extension is executable AND source is suspicious/unknown -> MALICIOUS
- If this looks like a legitimate file from a legitimate source -> SAFE

Return this exact JSON:
{
  "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
  "confidence": <float 0.0 to 1.0>,
  "explanation": "2-3 sentences in plain English for a non-technical user. What is this file? Is it safe? What should they do? Be specific about the source website if relevant.",
  "recommendedAction": "allow" | "warn" | "block",
  "indicators": ["up to 5 specific findings - mention source website risk if relevant"],
  "sourceRisk": "safe" | "suspicious" | "dangerous"
}`
}

export function buildDomainReputationPrompt(domain: string, reportCount: number, categories: string[]): string {
    return `You are a cybersecurity analyst. Summarize the threat reputation of this domain based on community reports. Return ONLY valid JSON.

Domain: ${domain}
Community Reports: ${reportCount}
Reported Categories: ${categories.join(', ') || 'none'}

Return:
{
  "summary": "1-2 sentence summary of this domain's threat reputation",
  "threatLevel": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "primaryThreat": "the main type of threat this domain poses",
  "recommendation": "avoid" | "caution" | "safe"
}`;
}

export function buildEmailPhishingPrompt(data: {
  sender: string
  subject: string
  body: string
  headers?: Record<string, string>
  timestamp?: string
}): string {
    const headerLines = data.headers
        ? Object.entries(data.headers).map(([k, v]) => `  - ${k}: ${v}`).join('\n')
        : '  - (none)';
    const bodyPreview = data.body.length > 2000 ? `${data.body.slice(0, 2000)}...` : data.body;
    return `You are an email security assistant. Analyze the email for phishing or scam indicators. Return ONLY valid JSON — no markdown, no code fences, no extra text.

Email:
  From: ${data.sender}
  Subject: ${data.subject}
  Timestamp: ${data.timestamp || 'unknown'}
Headers:
${headerLines}

Body (truncated):
${bodyPreview}

Return this exact JSON (no deviations):
{
  "isPhishing": <boolean>,
  "phishingScore": <number 0-100>,
  "confidence": <float 0.0 to 1.0>,
  "riskLevel": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "judgment": "1-2 sentence summary for a non-technical user",
  "indicators": {
    "phishingKeywords": ["..."],
    "domainIssues": ["..."],
    "authenticationFailures": ["..."],
    "suspiciousLinks": ["..."],
    "socialEngineering": ["..."],
    "malwareRisks": ["..."]
  },
  "recommendations": ["..."],
  "finalVerdict": "Short final verdict sentence"
}`;
}
