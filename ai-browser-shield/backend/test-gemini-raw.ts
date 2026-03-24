import { GoogleGenerativeAI } from '@google/generative-ai';
import { env } from './src/config';

async function testGeminiRaw() {
  const genAI = new GoogleGenerativeAI(env.GEMINI_API_KEY);
  const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' }, { apiVersion: 'v1beta' });

  try {
    console.log("Calling model...");
    const result = await model.generateContent({
      contents: [{ role: 'user', parts: [{ text: "Respond with JSON: {\"riskScore\": 10, \"riskLevel\": \"LOW\"}" }] }],
      generationConfig: {
        temperature: 0.1,
        responseMimeType: 'application/json'
      }
    });
    console.log("Success:", result.response.text());
  } catch (error: any) {
    console.error("RAW ERROR CAUGHT:");
    console.error(error);
    if (error.status) console.error("Status:", error.status);
    if (error.statusText) console.error("StatusText:", error.statusText);
    if (error.details) console.error("Details:", error.details);
  }
}

testGeminiRaw();
