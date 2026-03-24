// ── All Gemini prompts in one file ────────────────────────────────────────────
// Keeps prompts versioned and easy to iterate during hackathon

export function buildUrlScanPrompt(url: string, signals: Record<string, number>, riskScore: number): string {
  return `You are a cybersecurity expert analyzing URLs for phishing and malware. A browser extension has flagged this URL. Return ONLY valid JSON — no markdown, no code fences, no extra text.

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
}`
}

export function buildFileScanPrompt(data: {
  filename: string
  extension: string
  mimeType: string
  sizeBytes: number
  sourceUrl: string
  contentSnippet?: string
}): string {
  return `You are a malware analyst assessing whether a downloaded file is safe. Return ONLY valid JSON — no markdown, no code fences, no extra text.

File Information:
  Name: ${data.filename}
  Extension: ${data.extension}
  MIME Type: ${data.mimeType}
  Size: ${data.sizeBytes} bytes (${(data.sizeBytes / 1024).toFixed(1)} KB)
  Downloaded from: ${data.sourceUrl}
  Content preview: ${data.contentSnippet || 'N/A (binary file or not available)'}

Assess risk based on:
1. File extension vs MIME type mismatch (major red flag)
2. Executable extensions (.exe, .bat, .cmd, .ps1, .vbs, .js, .jar, .msi, .hta, .wsf, .scr, .pif, .com, .reg)
3. Archive formats that may contain hidden executables (.zip, .rar, .7z, .iso, .dmg)
4. Source URL trustworthiness (IP address vs domain, suspicious TLD)
5. Content snippet if available

Return this exact JSON (no deviations):
{
  "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
  "confidence": <float 0.0 to 1.0>,
  "explanation": "2-3 sentences in plain English for a non-technical user. What is this file, is it safe, and what should they do?",
  "recommendedAction": "keep" | "quarantine" | "delete",
  "indicators": ["up to 5 short phrases describing specific concerns or confirmations of safety"]
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
}`
}

export function buildEmailScanPrompt(data: {
  sender: string;
  subject: string;
  body: string;
  links: string[];
  localSignals: string[];
}): string {
  return `You are a forensic email security analyst. Analyze this email for phishing, social engineering, and fraud.

Email Details:
- From: ${data.sender}
- Subject: ${data.subject}
- Body Snippet: ${data.body.substring(0, 1000)}
- Links Found: ${data.links.join(', ')}
- Local Heuristics Flagged: ${data.localSignals.join(', ')}

Evaluate based on:
1. Sender Authenticity (CRITICAL): Does the sender email address (${data.sender}) look like a legitimate corporate account or a free/disguised one? Is it consistent with the content?
2. Social Engineering / Money Bait: Are they promising specific amounts of money (e.g., ₹5000, $1000) or rewards for clicking links?
3. Link Maliciousness: Are links hidden, shortened, or pointing to suspicious TLDs?

If the sender is a known legitimate service (like Internshala, LinkedIn) and the content is a standard notification, MARK IT AS SAFE.

Return ONLY valid JSON (no markdown):
{
  "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",
  "confidence": <float 0.0 to 1.0>,
  "explanation": "1-2 sentences in plain English explaining the decision.",
  "attackType": "Phishing" | "Scam" | "Malware" | "Spam" | "None",
  "recommendedAction": "ignore" | "report" | "delete"
}`;
}
