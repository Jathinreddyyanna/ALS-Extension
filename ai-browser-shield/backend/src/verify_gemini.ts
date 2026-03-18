import { analyzeWithGemini, pingGemini } from './services/ai.service';
import { logger } from './utils/logger';

async function verify() {
  console.log('--- Pinging Gemini ---');
  const pong = await pingGemini();
  console.log('Ping Result:', pong);
  // Log partially for safety
  const apiKey = (process.env.GEMINI_API_KEY || '').slice(0, 10) + '...';
  console.log('Using Model:', process.env.GEMINI_MODEL);
  console.log('API Key Starts With:', apiKey);
  if (!pong) {
    console.error('Gemini Ping Failed. Checking connectivity...');
  }
  const fileInput = {
    url: 'https://example.com/malicious.exe',
    hostname: 'example.com',
    path: '/malicious.exe',
    queryParams: {},
    heuristicScore: 85,
    heuristicSignals: {
        typosquat: 0,
        suspiciousTLD: 0,
        ipAsHostname: 0,
        longSubdomains: 0,
        suspiciousKeywords: 0,
        encodedChars: 0,
        pathEntropy: 0,
        portAnomaly: 0,
        credentialInUrl: 0,
        idnHomoglyph: 0,
        excessiveDots: 0,
        numericSubdomain: 0,
        tldMismatch: 0,
        repeatingSegments: 0,
        queryParamCount: 0,
        redirectParam: 0
    },
    domainReputation: {
      riskScore: 10,
      reportCount: 0,
      trustScore: 80,
      is_whitelisted: false
    },
    fileData: {
      filename: 'malicious.exe',
      mimeType: 'application/x-msdownload',
      sizeBytes: 102400,
      extension: '.exe',
      fileSampleBase64: 'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQokAAAAAAAAA...'
    },
    urlType: 'standard' as const,
    domain: 'example.com'
  };

  try {
    const result = await analyzeWithGemini(fileInput);
    console.log('File Scan Result:', JSON.stringify(result, null, 2));
  } catch (error) {
    console.error('File Scan Failed:', error);
  }

  console.log('\n--- Verifying URL Scan Prompt ---');
  const urlInput = {
    url: 'https://paypal-security-login.scam.top',
    hostname: 'paypal-security-login.scam.top',
    path: '/',
    queryParams: {},
    heuristicScore: 75,
    heuristicSignals: {
        typosquat: 1,
        suspiciousTLD: 1,
        ipAsHostname: 0,
        longSubdomains: 1,
        suspiciousKeywords: 1,
        encodedChars: 0,
        pathEntropy: 0,
        portAnomaly: 0,
        credentialInUrl: 0,
        idnHomoglyph: 0,
        excessiveDots: 0,
        numericSubdomain: 0,
        tldMismatch: 0,
        repeatingSegments: 0,
        queryParamCount: 0,
        redirectParam: 0
    },
    domainReputation: {
      riskScore: 0,
      reportCount: 0,
      trustScore: 50,
      is_whitelisted: false
    },
    urlType: 'standard' as const,
    domain: 'scam.top'
  };

  try {
    const result = await analyzeWithGemini(urlInput);
    console.log('URL Scan Result:', JSON.stringify(result, null, 2));
  } catch (error) {
    console.error('URL Scan Failed:', error);
  }
}

verify();
