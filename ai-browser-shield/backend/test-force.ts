import { performUrlScan } from './src/services/scan.service';
import { prisma } from './src/db/client';

async function test() {
  const url = 'https://example.com?gemini-test-force=true';
  console.log(`Scanning: ${url}`);
  const result = await performUrlScan({ url, signals: {} });
  console.log(JSON.stringify(result, null, 2));
}

test().finally(() => prisma.$disconnect());
