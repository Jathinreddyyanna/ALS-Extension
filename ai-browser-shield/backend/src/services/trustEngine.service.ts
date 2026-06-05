const TRUSTED_DOMAINS = new Set([
  'google.com',
  'google.co.in',
  'google.co.uk',
  'amazon.in',
  'amazon.com',
  'amazon.co.uk',
  'amazon.de',
  'paypal.com',
  'microsoft.com',
  'live.com',
  'office.com',
  'outlook.com',
  'apple.com',
  'github.com',
  'githubusercontent.com',
  'linkedin.com',
  'facebook.com',
  'instagram.com',
  'whatsapp.com',
  'youtube.com',
  'ebay.com',
  'stripe.com',
  'googleusercontent.com',
  'netflix.com',
  'openai.com',
  'chatgpt.com',
  'x.com',
  'twitter.com',
  'reddit.com',
  'cloudflare.com',
  'dropbox.com',
  'adobe.com',
  'canva.com',
  'notion.so',
  'salesforce.com',
  'zoom.us',
  'slack.com',
  'discord.com',
  'shopify.com',
  'walmart.com',
  'target.com',
  'flipkart.com',
  'sbi.co.in',
  'onlinesbi.sbi',
  'hdfcbank.com',
  'icicibank.com',
  'axisbank.com',
  'kotak.com',
  'bankofbaroda.in',
  'pnbindia.in',
  'chase.com',
  'bankofamerica.com',
  'wellsfargo.com',
  'citi.com'
]);

/**
 * Official TLDs that never require AI analysis - these are regulated and require official registration.
 */
const OFFICIAL_TLDS = [
  '.gov.in', '.nic.in', '.bank.in', '.fin.in', '.edu.in', '.ac.in', '.res.in', '.mil.in',
  '.gov', '.edu', '.mil', '.bank', '.insurance'
];

/**
 * Returns true when a hostname uses an official/regulated TLD.
 * These domains are guaranteed safe from impersonation due to strict registration requirements.
 */
export function isOfficialDomain(hostname: string): boolean {
  const clean = hostname.replace(/^www\./, '').toLowerCase();
  // Skip IP addresses
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(clean)) return false;
  return OFFICIAL_TLDS.some((tld) => clean.endsWith(tld));
}

/**
 * Returns true when a hostname belongs to a widely trusted service.
 */
export function isTrustedDomain(domain: string): boolean {
  const clean = domain.replace(/^www\./, '').toLowerCase();
  // Official TLDs are always trusted
  if (isOfficialDomain(clean)) {
    return true;
  }
  return Array.from(TRUSTED_DOMAINS).some((trustedDomain) => clean === trustedDomain || clean.endsWith(`.${trustedDomain}`));
}
