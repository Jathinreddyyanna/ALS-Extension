// COMPREHENSIVE ML BANNER TEST
// Run this in Gmail DevTools Console

console.log("=".repeat(60));
console.log("🧪 ML BANNER SYSTEM TEST");
console.log("=".repeat(60));

(async function fullTest() {
  try {
    // 1. Check if extension is loaded
    console.log("\n✅ Step 1: Checking ML Integration...");
    if (!window.__mlIntegration) {
      console.error("❌ __mlIntegration not found! Extension not loaded.");
      return;
    }
    console.log("✅ ML Integration found:", window.__mlIntegration);

    // 2. Extract current email
    console.log("\n✅ Step 2: Extracting email data...");
    const emailData = window.__mlIntegration.extractEmailFromGmail();
    if (!emailData) {
      console.error("❌ Could not extract email data");
      return;
    }
    console.log("✅ Email extracted:", {
      sender: emailData.sender,
      subject: emailData.subject.substring(0, 50),
      textLength: emailData.text.length
    });

    // 3. Test ML API
    console.log("\n✅ Step 3: Testing ML API...");
    const apiResponse = await fetch('http://localhost:5000/analyze-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(emailData)
    });

    if (!apiResponse.ok) {
      console.error("❌ API error:", apiResponse.status);
      return;
    }

    const mlResult = await apiResponse.json();
    console.log("✅ ML API Result:", mlResult);

    // 4. Create a test banner manually
    console.log("\n✅ Step 4: Creating test banner...");
    
    const testBanner = document.createElement('div');
    testBanner.id = 'ml-test-banner-full';
    testBanner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 999999;
      background: ${mlResult.risk_score >= 80 ? '#FEE2E2' : mlResult.risk_score >= 50 ? '#FFEDD5' : '#FEF3C7'};
      border-bottom: 3px solid ${mlResult.risk_score >= 80 ? '#EF4444' : mlResult.risk_score >= 50 ? '#F97316' : '#EAB308'};
      padding: 20px 24px;
      font-family: Arial, sans-serif;
    `;

    const emoji = mlResult.risk_score >= 80 ? '🚨' : mlResult.risk_score >= 50 ? '⚠️' : '⚡';
    const riskLabel = mlResult.risk_score >= 80 ? 'CRITICAL' : mlResult.risk_score >= 50 ? 'HIGH' : 'MEDIUM';

    testBanner.innerHTML = `
      <div style="display: flex; align-items: center; gap: 16px;">
        <div style="font-size: 40px;">${emoji}</div>
        <div>
          <div style="font-weight: bold; font-size: 18px; color: #111827;">
            ${riskLabel} RISK - Score: ${mlResult.risk_score}/100
          </div>
          <div style="color: #666; margin-top: 4px;">
            ${mlResult.explanation.risk_level}
          </div>
          <div style="margin-top: 8px; font-size: 13px; color: #666;">
            Detected: ${mlResult.detected_features.join(', ')}
          </div>
        </div>
      </div>
    `;

    document.body.insertBefore(testBanner, document.body.firstChild);
    console.log("✅ Test banner inserted! Should be visible at top of page");

    // 5. Keep banner for 10 seconds
    setTimeout(() => {
      testBanner.remove();
      console.log("\n✅ Test banner removed");
    }, 10000);

    console.log("\n" + "=".repeat(60));
    console.log("✅ TEST COMPLETE - Banner should be visible for 10 seconds");
    console.log("=".repeat(60));

  } catch (error) {
    console.error("❌ Test failed:", error);
    console.error("Stack:", error.stack);
  }
})();
