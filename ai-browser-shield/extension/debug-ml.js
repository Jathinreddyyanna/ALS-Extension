// DEBUG: Force re-analyze email and show detailed logs
(async function debugML() {
  console.log('🔧 DEBUG: Starting forced analysis...');
  
  // Clear cache
  window.__mlIntegration_lastAnalyzedEmailId = null;
  
  try {
    // Extract email
    const emailData = window.__mlIntegration.extractEmailFromGmail();
    console.log('📧 Extracted email:', emailData);
    
    if (!emailData) {
      console.error('❌ Failed to extract email data');
      return;
    }
    
    // Call API directly
    console.log('🔄 Calling ML backend...');
    const response = await fetch('http://localhost:5000/analyze-email', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(emailData)
    });
    
    const result = await response.json();
    console.log('✅ ML Result:', result);
    
    // Test banner creation
    console.log('🎨 Testing banner creation...');
    
    // Check if banner can be inserted
    const testDiv = document.createElement('div');
    testDiv.id = 'ml-test-banner';
    testDiv.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      z-index: 999999;
      background: #FEE2E2;
      border-bottom: 3px solid #EF4444;
      padding: 20px;
      text-align: center;
      font-size: 18px;
      font-weight: bold;
      color: #DC2626;
    `;
    testDiv.textContent = `🚨 TEST BANNER - Risk Score: ${result.risk_score}/100`;
    
    document.body.insertBefore(testDiv, document.body.firstChild);
    console.log('✅ Test banner inserted!');
    
    // Check if it exists in DOM
    const exists = document.getElementById('ml-test-banner');
    console.log('🔍 Banner exists in DOM:', !!exists);
    
    // Remove after 5 seconds
    setTimeout(() => {
      testDiv.remove();
      console.log('🗑️ Test banner removed');
    }, 5000);
    
  } catch (error) {
    console.error('❌ Debug failed:', error);
  }
})();
