import { logError } from '../common/logger'

const SPAM_KEYWORDS = [
  "urgent", "immediate", "immediately", "final notice", "last chance",
  "act now", "limited time", "account blocked", "account suspended",
  "action required", "verify immediately", "verify account", "login now",
  "update details", "reset password", "confirm account", "unauthorized access",
  "security alert", "bank account", "upi", "atm", "credit card", "debit card",
  "kyc", "otp", "transaction failed", "click link", "click here",
  "winner", "lottery", "prize", "reward", "free gift", "free money",
  "instant loan", "quick loan", "pre-approved", "no cibil",
  "bitcoin", "crypto", "high return", "investment plan",
  "parcel on hold", "delivery failed", "customs clearance",
  "virus detected", "remote access", "system infected",
  "government scheme", "subsidy", "grant approved", "relief fund",
  "registration fee", "shortlisted", "google form"
];

const PHISHING_SYSTEM_PROMPT = `You are the AI security engine inside a Chrome extension called "AI Browser Shield".

Your task is to analyze email text and detect phishing attempts with very high accuracy.

Your users are Indian internet users including students, elderly people, and first-time smartphone users. Your explanation must be simple enough for a 60-year-old grandmother to understand.

GOALS:
1. Detect phishing with maximum accuracy
2. Avoid false alarms for legitimate emails
3. Explain clearly what trick the attacker is using
4. Be aware of Indian banking and government brands

EMAIL PHISHING SIGNALS TO DETECT

Psychological Manipulation:
- URGENCY → "act now", "24 hours", "immediate action"
- FEAR → "account blocked", "legal action", "penalty"
- AUTHORITY → fake bank, RBI, government warnings
- SCARCITY → "last chance", "limited time"
- GREED → "you won", "prize", "refund"
- SOCIAL → "your friend shared", "family emergency"

Common Indian Phishing Attacks:
- Fake KYC update requests
- UPI account blocked scams
- Fake IRCTC refunds
- Aadhaar verification scams
- Fake job offers requiring payment
- Fake loan approvals
- Fake parcel delivery failure
- OTP harvesting attempts
- Electricity bill payment scams

Suspicious URL Patterns:
- Domain impersonation (hdfc-secure.in vs hdfcbank.com)
- Typosquatting (paypa1.com or arnazon.in)
- Suspicious TLD (.tk, .xyz, .top, .ml)
- IP address login pages
- URL shorteners (bit.ly, tinyurl)

Legitimate Email Signals (reduce risk):
- Professional sign-off ("Regards", "Sincerely")
- Official receipts or invoices
- Replies to existing email thread
- University or academic communication
- Government circular style communication

SCORING RULES
- 90-100 → Confirmed phishing attack
- 70-89 → High risk phishing
- 40-69 → Suspicious email
- 10-39 → Low risk
- 0-9 → Clean email

IMPORTANT SECURITY FACTS
- Indian banks never ask for OTP, password, or card details by email
- Government departments never ask for payments through email links
- Real IRCTC refunds happen automatically
- Real KYC updates are done through official banking apps or branch visits

OUTPUT FORMAT (JSON ONLY - no markdown, no explanations outside JSON):

{
  "riskScore": number,
  "riskLabel": "safe" | "suspicious" | "dangerous",
  "attackType": "Credential Harvesting" | "Financial Fraud" | "Identity Theft" | "Malware Delivery" | "Lottery Scam" | "Job Scam" | "Delivery Scam" | "KYC Fraud" | "Brand Impersonation" | "None",
  "indianBrandImpersonated": "HDFC" | "SBI" | "IRCTC" | "Aadhaar" | "UPI" | "RBI" | "Paytm" | "Jio" | "Airtel" | "None",
  "psychologicalTriggers": [
    {
      "trigger": "URGENCY" | "AUTHORITY" | "FEAR" | "SCARCITY" | "GREED" | "SOCIAL",
      "evidence": "exact phrase from email",
      "explanation": "why it manipulates the user"
    }
  ],
  "suspiciousUrls": [
    {
      "url": "detected url",
      "reason": "why it is suspicious",
      "realDomain": "correct legitimate domain"
    }
  ],
  "explanation": "Explain in simple language what the email pretends to be, the trick used, and what the user must NOT do. Maximum 80 words.",
  "safeAction": "One sentence telling the user what they should do instead.",
  "confidence": number
}
`;

const HAM_KEYWORDS = [
  "regards", "sincerely", "best wishes", "official email",
  "privacy policy", "terms of service", "invoice attached",
  "payment receipt", "transaction receipt", "meeting", "schedule",
  "assignment submission", "hall ticket", "semester", "attendance"
];

const URGENCY = ["urgent","immediate","immediately","act now","final notice","last chance","limited time","action required","verify immediately"];
const AUTHORITY = ["rbi","hdfc","sbi","irctc","aadhaar","upi","government","official","security alert","bank"];
const FEAR = ["account blocked","account suspended","unauthorized access","transaction failed","system infected","virus detected"];
const SCARCITY = ["limited time","limited offer","last chance","exclusive offer","final notice"];

const TRUSTED_DOMAINS = [
  "kotak.com",
  "hdfcbank.com",
  "sbi.co.in",
  "irctc.co.in",
  "amazon.in",
  "paytm.com",
  "flipkart.com",
  "uber.com"
];

const SUSPICIOUS_LINKS = [
  "bit.ly",
  "tinyurl",
  "verify-account",
  "login-secure",
  "update-kyc",
  "confirm-identity",
  "validate-account",
  "below link",
  "click the link",
  "google form"
];

const JOB_SCAM_PATTERNS = [
  /internship/i,
  /stipend/i,
  /per\s*month/i,
  /work\s*from\s*home/i,
  /registration\s*fee/i,
  /offer\s*letter/i,
  /shortlisted/i,
  /campus\s*drive/i,
  /hr\s*team/i,
];

export interface EmailAnalysis {
  riskScore: number;
  riskLabel: 'safe' | 'suspicious' | 'dangerous';
  attackType: string;
  triggers: { type: string; evidence: string }[];
  detectedPatterns: string[];
  explanation: string;
  indianBrand: string;
  confidence?: number;
  signals?: { name: string; score: number }[];
  isSpamFolder?: boolean;
}

const OBVIOUSLY_FAKE_DOMAINS = [
  "tempmail", "throwaway", "guerrillamail", "mailinator",
  "10minutemail", "yopmail", "sharklasers", "fakeinbox", "trashmail"
];

const SUSPICIOUS_TLDS_LIST = [".xyz", ".tk", ".top", ".ml", ".gq"];

function checkSenderReputation(senderEmail: string): number {
  if (!senderEmail) return 0;
  
  const domain = senderEmail.toLowerCase().split("@")[1] || "";
  
  // Check for obviously fake/disposable email domains
  if (OBVIOUSLY_FAKE_DOMAINS.some(fake => domain.includes(fake))) {
    return 50; // Very suspicious
  }
  
  // Check for trusted domains
  if (TRUSTED_DOMAINS.some(t => domain.includes(t))) {
    return -25; // Reduce score for trusted domains
  }
  
  // Check for suspicious TLDs
  if (SUSPICIOUS_TLDS_LIST.some(tld => domain.endsWith(tld))) {
    return 40; // Suspicious TLD
  }
  
  return 0;
}

function checkSenderDomain(emailText: string): number {
  // Kept for backward compatibility but now just returns 0
  // Real sender reputation check is done in checkSenderReputation
  return 0;
}

function checkLinks(emailText: string): number {
  const lowerText = emailText.toLowerCase();
  for (const link of SUSPICIOUS_LINKS) {
    if (lowerText.includes(link)) return 25;
  }
  return 0;
}

function checkUrgency(emailText: string): number {
  const urgencyWords = ["urgent", "immediately", "account suspended", "verify now", "action required"];
  const lowerText = emailText.toLowerCase();
  let score = 0;
  for (const word of urgencyWords) {
    if (lowerText.includes(word)) score += 10;
  }
  return Math.min(score, 50);
}

function checkJobScam(emailText: string): number {
  const text = emailText.toLowerCase();
  const hits = JOB_SCAM_PATTERNS.filter((pattern) => pattern.test(text)).length;

  const hasLureAmount = /(?:₹|rs\.?\s*)\s*\d+/i.test(text) || /\b\d+\s*k\b/i.test(text);
  const hasActionBait = /click|apply now|fill form|verify|submit details|registration/i.test(text);

  let score = hits * 6;
  if (hasLureAmount) score += 12;
  if (hasActionBait) score += 10;

  return Math.min(35, score);
}

function checkBrandMismatch(senderEmail: string, emailText: string): number {
  if (!senderEmail) return 0;

  const lowerText = emailText.toLowerCase();
  const senderLower = senderEmail.toLowerCase();
  const brands = ["amazon", "paypal", "google", "microsoft", "apple", "facebook", "netflix", "hdfc", "sbi", "icici", "internshala"];

  for (const brand of brands) {
    if (lowerText.includes(brand) && !senderLower.includes(brand)) {
      return 25;
    }
  }

  return 0;
}

export function analyseEmailLocally(emailText: string, senderEmail: string = '', isSpamFolder: boolean = false): EmailAnalysis {
  const text = emailText.toLowerCase()
  
  // If sender wasn't provided, try to extract from body text as fallback
  if (!senderEmail) {
    const fromMatch = emailText.match(/From:?\s*([^\n<]+?)(?:<|$|\n)/i)
    if (fromMatch) {
      const parsed = fromMatch[1].trim()
      const emailMatch = parsed.match(/[\w\.-]+@[\w\.-]+\.\w+/)
      if (emailMatch) {
        senderEmail = emailMatch[0]
      }
    }
  }
  
  // Count spam vs ham
  const spamHits = SPAM_KEYWORDS.filter(k => text.includes(k));
  const hamHits = HAM_KEYWORDS.filter(k => text.includes(k));
  
  // Detect psychological triggers
  const triggers: { type: string; evidence: string }[] = [];
  
  URGENCY.forEach(k => {
    if (text.includes(k)) triggers.push({ type: 'URGENCY', evidence: k });
  });
  AUTHORITY.forEach(k => {
    if (text.includes(k)) triggers.push({ type: 'AUTHORITY', evidence: k });
  });
  FEAR.forEach(k => {
    if (text.includes(k)) triggers.push({ type: 'FEAR', evidence: k });
  });
  SCARCITY.forEach(k => {
    if (text.includes(k)) triggers.push({ type: 'SCARCITY', evidence: k });
  });

  // Detect Indian brand impersonation
  const brands = ['hdfc', 'sbi', 'irctc', 'aadhaar', 'paytm', 'upi', 'npci', 'rbi'];
  const indianBrand = brands.find(b => text.includes(b))?.toUpperCase() || 'None';

  // Multi-signal scoring
  let riskScore = 0;
  const signals: { name: string; score: number }[] = [];
  
  // Signal 1: Keyword spam score
  const spamScore = Math.min(70, spamHits.length * 8);
  riskScore += spamScore;
  signals.push({ name: "Spam keywords", score: spamScore });
  
  // Signal 2: Psychological trigger score
  const triggerScore = Math.min(20, triggers.length * 5);
  riskScore += triggerScore;
  signals.push({ name: "Psychological triggers", score: triggerScore });
  
  // Signal 3: Brand impersonation score
  const brandScore = indianBrand !== 'None' ? 10 : 0;
  riskScore += brandScore;
  signals.push({ name: "Brand impersonation", score: brandScore });
  
  // Signal 4: Sender reputation (using actual sender email)
  const senderRepScore = checkSenderReputation(senderEmail);
  riskScore += senderRepScore;
  signals.push({ name: "Sender reputation", score: senderRepScore });
  
  // Signal 5: Suspicious link detection
  const linkScore = checkLinks(emailText);
  riskScore += linkScore;
  signals.push({ name: "Suspicious links", score: linkScore });
  
  // Signal 6: Urgency language
  const urgencyScore = checkUrgency(emailText);
  riskScore += urgencyScore;
  signals.push({ name: "Urgency language", score: urgencyScore });

  // Signal 7: Brand mismatch
  const brandMismatchScore = checkBrandMismatch(senderEmail, emailText);
  riskScore += brandMismatchScore;
  signals.push({ name: "Brand mismatch", score: brandMismatchScore });

  // Signal 8: Gmail spam folder
  const spamFolderBoost = isSpamFolder ? 40 : 0;
  riskScore += spamFolderBoost;
  signals.push({ name: "Gmail spam folder", score: spamFolderBoost });

  // Signal 9: Job/internship fraud bait
  const jobScamScore = checkJobScam(emailText);
  riskScore += jobScamScore;
  signals.push({ name: "Job scam pattern", score: jobScamScore });
  
  // Apply ham penalty
  const hamPenalty = Math.min(30, hamHits.length * 5);
  riskScore -= hamPenalty;
  signals.push({ name: "Ham indicators", score: -hamPenalty });
  
  // Clamp score
  riskScore = Math.min(100, Math.max(0, riskScore));

  // Label
  const riskLabel = riskScore > 60 ? 'dangerous' 
                  : riskScore > 25 ? 'suspicious' 
                  : 'safe';

  // Calculate confidence
  const positiveSignals = signals.filter(s => s.score > 5).length;
  const confidence = Math.round((positiveSignals / signals.length) * 100 + (riskScore / 100) * 30);

  // Attack type
  const attackType = text.includes('loan') || text.includes('investment') ? 'Financial Fraud'
    : text.includes('password') || text.includes('otp') || text.includes('verify') ? 'Credential Harvesting'
    : text.includes('lottery') || text.includes('prize') ? 'Lottery Scam'
    : text.includes('delivery') || text.includes('parcel') ? 'Delivery Scam'
    : indianBrand !== 'None' ? 'Brand Impersonation'
    : riskLabel !== 'safe' ? 'Phishing Attempt'
    : 'None';

  // Unique patterns only
  const detectedPatterns = [...new Set(triggers.map(t => t.evidence))].slice(0, 6);

  const explanation = riskLabel === 'dangerous'
    ? `High-risk phishing style detected. This message uses pressure or reward bait and requests actions that can steal money or credentials.`
    : riskLabel === 'suspicious'
      ? `This email has suspicious manipulation signals. Verify sender and links through official channels before taking action.`
      : `This email appears relatively safe based on current checks.`;

  return {
    riskScore,
    riskLabel,
    attackType,
    triggers: triggers.slice(0, 5),
    detectedPatterns,
    explanation,
    indianBrand,
    confidence,
    signals,
    isSpamFolder,
  };
}

// Helper: Safe JSON parsing with fallback
function safeParseGemini(text: string) {
  try {
    const start = text.indexOf("{");
    const end = text.lastIndexOf("}");
    if (start === -1 || end === -1) throw new Error("No JSON found");
    const json = text.slice(start, end + 1);
    return JSON.parse(json);
  } catch (e) {
    return {
      riskScore: 50,
      riskLabel: "suspicious",
      attackType: "None",
      indianBrandImpersonated: "None",
      psychologicalTriggers: [],
      suspiciousUrls: [],
      explanation: "The email could not be analyzed fully. Please verify the sender before taking action.",
      safeAction: "Do not click links. Verify using the official website.",
      confidence: 0.5
    };
  }
}

// Helper: Extract and flag suspicious URLs
function extractSuspiciousUrls(emailText: string): string[] {
  const urls = emailText.match(/https?:\/\/[^\s]+/g) || [];
  const suspiciousTLDs = [".xyz", ".tk", ".top", ".gq", ".ml"];
  return urls.filter(url => suspiciousTLDs.some(tld => url.includes(tld)));
}

// Helper: Detect brand mismatch between sender and email content
function detectBrandMismatch(senderEmail: string, emailText: string): string | null {
  const brands: Record<string, string> = {
    "hdfc": "hdfcbank.com",
    "sbi": "sbi.co.in",
    "irctc": "irctc.co.in",
    "aadhaar": "uidai.gov.in",
    "paytm": "paytm.com"
  };

  const lowerText = emailText.toLowerCase();
  const lowerSender = senderEmail.toLowerCase();

  for (const brand in brands) {
    if (lowerText.includes(brand) && !lowerSender.includes(brands[brand])) {
      return brand.toUpperCase();
    }
  }
  return null;
}

// Helper: Offline fallback scoring (no Gemini)
function offlinePhishingScore(emailText: string): { score: number; reason: string } {
  let score = 0;
  const lowerText = emailText.toLowerCase();

  // Urgency score
  const urgencyPhrases = ["verify now", "account blocked", "action required", "24 hours", "immediate"];
  const urgencyCount = urgencyPhrases.filter(p => lowerText.includes(p)).length;
  score += urgencyCount * 15;

  // Suspicious TLDs
  const suspiciousUrls = extractSuspiciousUrls(emailText);
  score += suspiciousUrls.length * 20;

  // Brand mismatch (no sender to check, but flag if branded)
  if (["hdfc", "sbi", "irctc"].some(b => lowerText.includes(b))) {
    score += 15;
  }

  // Shortened URLs
  if (lowerText.includes("bit.ly") || lowerText.includes("tinyurl")) {
    score += 25;
  }

  score = Math.min(100, score);
  return { score, reason: "Local scoring (Gemini unavailable)" };
}

export async function getGeminiExplanation(
  emailText: string,
  localAnalysis: EmailAnalysis
): Promise<string> {
  try {
    const fromMatch = emailText.match(/From:?\s*([^\n<]+?)(?:<|$|\n)/i)
    const sender = fromMatch ? fromMatch[1].trim() : "Unknown sender"
    
    const subjectMatch = emailText.match(/Subject:?\s*([^\n]+)/i)
    const subject = subjectMatch ? subjectMatch[1].trim() : "No subject"

    const prompt = `${PHISHING_SYSTEM_PROMPT}

EMAIL SENDER: ${sender}

EMAIL SUBJECT: ${subject}

EMAIL BODY:
${emailText.slice(0, 1000)}`

    const geminiApiKey = import.meta.env.VITE_GEMINI_API_KEY;
    
    if (!geminiApiKey) {
      // Fallback if no API key
      const offline = offlinePhishingScore(emailText);
      return `AI unavailable – using local protection. Score: ${offline.score}/100. ${offline.reason}`;
    }

    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${geminiApiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [
            {
              parts: [
                {
                  text: prompt
                }
              ]
            }
          ]
        })
      }
    );
    
    if (!response.ok) {
      const offline = offlinePhishingScore(emailText);
      return `AI temporarily unavailable – using local protection. ${offline.reason}`;
    }

    const data = await response.json();
    const responseText = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
    
    // Safe JSON parsing
    const parsed = safeParseGemini(responseText);
    return parsed.explanation || generateFallbackExplanation(localAnalysis);
  } catch (error) {
    logError('AI', 'Gemini API error:', error)
    const offline = offlinePhishingScore(emailText);
    return `Error calling AI. Local protection active: ${offline.reason}`;
  }
}

function generateFallbackExplanation(analysis: EmailAnalysis): string {
  if (analysis.riskLabel === 'dangerous') {
    return `This email shows ${analysis.triggers.length} manipulation tactics including ${analysis.triggers[0]?.type.toLowerCase() || 'urgency'}. It appears to be a ${analysis.attackType} attempt. Do not click any links or share personal information.`;
  }
  if (analysis.riskLabel === 'suspicious') {
    return `This email has some suspicious characteristics. Exercise caution before clicking links or providing any information.`;
  }
  return `This email appears safe. No significant phishing patterns were detected.`;
}
