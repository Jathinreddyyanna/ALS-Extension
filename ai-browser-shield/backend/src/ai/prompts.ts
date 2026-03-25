export function buildUrlScanPrompt(url: string, signals: Record<string, number>, riskScore: number): string {
  return `You are a cybersecurity expert analyzing URLs for phishing and malware. A browser extension has flagged this URL. Return ONLY valid JSON - no markdown, no code fences, no extra text.

URL: ${url}
Overall Risk Score: ${riskScore}/100

Signals detected:
${Object.entries(signals).map(([key, value]) => `  - ${key}: ${value}`).join('\n')}

Return this exact JSON:
{
  "explanation": "2-3 plain-English sentences for a non-technical user.",
  "riskLevel": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "recommendedAction": "allow" | "warn" | "block",
  "confidence": <float 0.0 to 1.0>,
  "keyIndicators": ["up to 3 short phrases"]
}`;
}

export function buildFileScanPrompt(data: {
  filename: string;
  extension: string;
  mimeType: string;
  sizeBytes: number;
  sourceUrl: string;
  contentSnippet?: string;
}): string {
  return `You are a malware analyst assessing whether a downloaded file is safe. Return ONLY valid JSON - no markdown, no code fences, no extra text.

File Information:
  Name: ${data.filename}
  Extension: ${data.extension}
  MIME Type: ${data.mimeType}
  Size: ${data.sizeBytes} bytes
  Downloaded from: ${data.sourceUrl}
  Content preview: ${data.contentSnippet || 'N/A'}

Return this exact JSON:
{
  "verdict": "SAFE" | "SUSPICIOUS" | "MALICIOUS",
  "confidence": <float 0.0 to 1.0>,
  "explanation": "2-3 plain-English sentences.",
  "recommendedAction": "keep" | "quarantine" | "delete",
  "indicators": ["up to 5 short phrases"]
}`;
}

export function buildDomainReputationPrompt(domain: string, reportCount: number, categories: string[]): string {
  return `You are a cybersecurity analyst. Summarize the threat reputation of this domain based on community reports. Return ONLY valid JSON.

Domain: ${domain}
Community Reports: ${reportCount}
Reported Categories: ${categories.join(', ') || 'none'}

Return:
{
  "summary": "1-2 sentence summary",
  "threatLevel": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "primaryThreat": "main type of threat",
  "recommendation": "avoid" | "caution" | "safe"
}`;
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

Evaluate:
1. Sender authenticity and impersonation risk.
2. Social engineering, urgency, money bait, credential theft, or attachment bait.
3. Suspicious links, hidden destinations, shortened URLs, or suspicious TLDs.
4. If the sender is a known legitimate service and the content is a standard notification, mark it SAFE.

Return ONLY valid JSON:
{
  "verdict": "SAFE" | "SUSPICIOUS" | "DANGEROUS",
  "confidence": <float 0.0 to 1.0>,
  "explanation": "1-2 plain-English sentences explaining the decision.",
  "attackType": "Phishing" | "Scam" | "Malware" | "Spam" | "None",
  "recommendedAction": "ignore" | "report" | "delete"
}`;
}

export function buildEmailThreatExplanationPrompt(data: {
  sender: string;
  subject: string;
  body: string;
  phishingProbability: number;
  decision: 'SAFE' | 'WARNING' | 'BLOCK';
  topFeatures: string[];
  localSignals: string[];
}): string {
  return `You are a phishing email analyst writing a concise explanation for an end user. Return ONLY valid JSON.

Email:
- Sender: ${data.sender}
- Subject: ${data.subject}
- Body snippet: ${data.body.slice(0, 1200)}
- ML phishing probability: ${Math.round(data.phishingProbability * 100)}%
- Decision: ${data.decision}
- Top ML features: ${data.topFeatures.join(', ') || 'none'}
- Local heuristic signals: ${data.localSignals.join(', ') || 'none'}

Return:
{
  "explanation": "2-3 plain English sentences. Mention the most important risk indicators and what the user should do next.",
  "attackType": "Phishing" | "Credential Theft" | "Brand Impersonation" | "Malware" | "Scam" | "Spam" | "None",
  "recommendedAction": "ignore" | "report" | "delete"
}`;
}
