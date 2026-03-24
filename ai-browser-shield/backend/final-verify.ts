import { performUrlScan } from './src/services/scan.service';
import { prisma } from './src/db/client';

async function testSuite() {
  const domains = [
    'https://google.com',
    'https://example.com',
    'https://5movierulz.codes',
    'https://sbi-netbanking-verify.co.in'
  ];

  console.log("Starting Comprehensive Test Suite...");
  
  for (const url of domains) {
    try {
      console.log(`\n--- Scanning: ${url} ---`);
      const result = await performUrlScan({
        url,
        signals: {},
        requestContext: { referrer: '', tabCount: 1, timeOnPage: 0 }
      });
      
      console.log(`URL: ${url}`);
      console.log(`Risk Level: ${result.riskLevel}`);
      console.log(`Risk Score: ${result.riskScore}`);
      console.log(`AI Source: ${result.aiSource}`);
      console.log(`Decision Basis: ${result.decisionBasis}`);
      console.log(`Explanation: ${result.explanation}`);
    } catch (error) {
      console.error(`Error scanning ${url}:`, error);
    }
  }
}

testSuite().finally(() => prisma.$disconnect());
