import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

const whitelistDomains = [
  'google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
  'linkedin.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com',
  'wikipedia.org', 'reddit.com', 'stackoverflow.com', 'cloudflare.com', 'stripe.com',
  'paypal.com', 'dropbox.com', 'slack.com', 'zoom.us', 'figma.com', 'notion.so',
  'vercel.app', 'netlify.app', 'heroku.com', 'nasa.gov', 'nih.gov', 'cdc.gov',
  'who.int', 'un.org', 'europa.eu'
];

const knownBadDomains = [
  'secure-paypal-login.com', 'apple-id-verify.net', 'amazon-account-suspended.net', 'microsoft-security-alert.com', 'netflix-billing-update.net',
  'coinbase-wallet-verify.com', 'binance-airdrop-claim.net', 'facebook-login-secure.com', 'instagram-verify-account.net', 'gmail-security-alert.com',
  'outlook-mailbox-recovery.net', 'github-auth-warning.com', 'linkedin-premium-expired.net', 'dropbox-shared-document.com', 'slack-workspace-alert.net',
  'zoom-meeting-security.com', 'stripe-payout-review.net', 'chase-account-locked.com', 'wellsfargo-secure-alert.net', 'citibank-card-review.com',
  'hsbc-customer-update.net', 'bankofamerica-session-alert.com', 'paypal-resolution-center.net', 'apple-wallet-security.com', 'google-drive-share-alert.net',
  'icloud-storage-warning.com', 'aws-console-security.net', 'azure-tenant-verify.com', 'cloudflare-zone-alert.net', 'shopify-store-billing.com',
  'adobe-pdf-share-alert.net', 'docusign-envelope-review.com', 'telegram-premium-alert.net', 'discord-nitro-security.com', 'metamask-wallet-secure.net',
  'uniswap-reward-claim.com', 'opensea-auth-review.net', 'robinhood-broker-alert.com', 'kraken-wallet-verify.net', 'spotify-account-warning.com',
  'youtube-channel-security.net', 'tiktok-business-alert.com', 'snapchat-login-review.net', 'reddit-mod-security.com', 'booking-refund-review.net',
  'airbnb-reservation-alert.com', 'fedex-customs-invoice.net', 'dhl-package-hold.com', 'usps-tracking-review.net', 'irs-refund-notice.com'
];

// Fake test hashes only. These are not real malware samples.
const maliciousFiles = [
  {
    sha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    md5: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    filename: 'invoice-sample.exe',
    mimeType: 'application/octet-stream',
    sizeBytes: BigInt(1024)
  },
  {
    sha256: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    md5: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    filename: 'bank-alert.scr',
    mimeType: 'application/x-msdownload',
    sizeBytes: BigInt(2048)
  },
  {
    sha256: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    md5: 'cccccccccccccccccccccccccccccccc',
    filename: 'wallet-update.msi',
    mimeType: 'application/x-msi',
    sizeBytes: BigInt(4096)
  },
  {
    sha256: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    md5: 'dddddddddddddddddddddddddddddddd',
    filename: 'security-patch.js',
    mimeType: 'application/javascript',
    sizeBytes: BigInt(8192)
  },
  {
    sha256: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    md5: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    filename: 'urgent-doc.zip',
    mimeType: 'application/zip',
    sizeBytes: BigInt(16384)
  }
];

const main = async () => {
  let whitelistUpserts = 0;
  for (const domain of whitelistDomains) {
    await prisma.domainScore.upsert({
      where: { domain },
      update: { isWhitelisted: true, riskScore: 0, trustScore: 95, categories: [] },
      create: { domain, isWhitelisted: true, riskScore: 0, trustScore: 95, categories: [] }
    });
    whitelistUpserts += 1;
  }
  console.log(`whitelist domains upserted: ${whitelistUpserts} entries`);

  let knownBadUpserts = 0;
  for (const domain of knownBadDomains) {
    await prisma.domainScore.upsert({
      where: { domain },
      update: { isConfirmed: true, riskScore: 90, categories: ['phishing'], trustScore: 5, reportCount: 5 },
      create: { domain, isConfirmed: true, riskScore: 90, categories: ['phishing'], trustScore: 5, reportCount: 5 }
    });
    knownBadUpserts += 1;
  }
  console.log(`known bad domains upserted: ${knownBadUpserts} entries`);

  let maliciousFileUpserts = 0;
  for (const file of maliciousFiles) {
    await prisma.maliciousFile.upsert({
      where: { sha256: file.sha256 },
      update: {
        md5: file.md5,
        filename: file.filename,
        mimeType: file.mimeType,
        sizeBytes: file.sizeBytes,
        verdict: 'MALICIOUS',
        confidence: 1,
        source: 'admin'
      },
      create: {
        sha256: file.sha256,
        md5: file.md5,
        filename: file.filename,
        mimeType: file.mimeType,
        sizeBytes: file.sizeBytes,
        verdict: 'MALICIOUS',
        confidence: 1,
        source: 'admin'
      }
    });
    maliciousFileUpserts += 1;
  }
  console.log(`malicious files upserted: ${maliciousFileUpserts} entries`);
};

void main().finally(async () => {
  await prisma.$disconnect();
});
