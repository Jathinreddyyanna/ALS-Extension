import { getGeminiDebugResult } from './src/services/ai.service';
import { generateExplanation } from './src/services/explanation.service';

async function test() {
  console.log("Testing direct explanation service...");
  try {
    const result = await generateExplanation({
      normalizedUrl: "https://example.com",
      domain: "example.com",
      urlType: "standard",
      riskScore: 11,
      decisionBasis: "low_risk_reputation",
      isWhitelisted: false,
      reputationStatus: "unknown",
      signals: ["Secure HTTPS connection", "DNS resolved normally"]
    });
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error("Error running explanation:", error);
  }
}

test();
