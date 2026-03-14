document.addEventListener('DOMContentLoaded', () => {
  const riskBadge = document.getElementById('risk-badge');
  const riskScore = document.getElementById('risk-score');
  const platformName = document.getElementById('platform-name');
  const explanationText = document.getElementById('explanation-text');
  const patternsList = document.getElementById('patterns-list');
  const patternsTitle = document.getElementById('patterns-title');
  const riskCard = document.getElementById('risk-card');

  // Load analysis data from storage
  chrome.storage.local.get(['currentAnalysis', 'processingState'], (result) => {
    if (result && result.processingState) {
      // Show processing state with rainbow border
      showProcessingState();
    } else if (result && result.currentAnalysis) {
      renderAnalysis(result.currentAnalysis);
    } else {
      // Default state
      explanationText.textContent = "No content analyzed yet. Open an email or chat.";
    }
  });

  // Listen for storage changes to update UI in real-time
  chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local') {
      if (changes.processingState && changes.processingState.newValue) {
        showProcessingState();
      } else if (changes.currentAnalysis && changes.currentAnalysis.newValue) {
        renderAnalysis(changes.currentAnalysis.newValue);
      }
    }
  });


  function showProcessingState() {
    // Add rainbow border to risk card
    riskCard.classList.add('processing');
    
    // Update badge
    riskBadge.textContent = 'ANALYZING';
    riskBadge.className = 'risk-badge';
    riskBadge.style.backgroundColor = '#6c63ff';
    riskBadge.style.color = '#fff';
    
    // Update score
    riskScore.innerHTML = '... <span>Processing</span>';
    
    // Update explanation
    explanationText.textContent = 'AI is analyzing this content for potential risks...';
    explanationText.style.borderLeftColor = '#6c63ff';
    
    // Clear patterns
    patternsList.innerHTML = '';
    patternsTitle.style.display = 'none';
  }

  function renderAnalysis(data) {
    // Data fields: final_risk_label, final_score, explanation, platform, detected_patterns

    // 1. Badge & Color
    const label = data.final_risk_label || 'safe';
    riskBadge.textContent = label.toUpperCase();

    // Remove processing state
    riskCard.classList.remove('processing');
    
    // Clear old classes
    riskBadge.className = 'risk-badge';
    riskCard.style.borderTop = 'none';

    if (label === 'dangerous') {
      riskBadge.classList.add('dangerous');
      explanationText.style.borderLeftColor = '#ff3b3b';
      riskCard.style.borderTop = '4px solid #ff3b3b';
    } else if (label === 'suspicious') {
      riskBadge.classList.add('suspicious');
      explanationText.style.borderLeftColor = '#ffcc00';
      riskCard.style.borderTop = '4px solid #ffcc00';
    } else {
      riskBadge.classList.add('safe');
      explanationText.style.borderLeftColor = '#2ecc40';
      riskCard.style.borderTop = '4px solid #2ecc40';
    }

    // 2. Score
    // Convert 0-1 to percentage and cap at 100%
    const percentage = Math.min(100, Math.round((data.final_score || 0) * 100));
    riskScore.innerHTML = `${percentage}% <span>Risk Score</span>`;

    // 3. Platform
    platformName.textContent = (data.platform || 'UNKNOWN').toUpperCase();

    // 4. Explanation
    explanationText.textContent = data.explanation || "No risk details provided.";

    // 5. Detected Patterns
    patternsList.innerHTML = '';
    const patterns = data.detected_patterns || [];

    if (patterns.length > 0) {
      patternsTitle.style.display = 'block';
      patterns.forEach(p => {
        const tag = document.createElement('div');
        tag.className = 'pattern-tag';
        if (label !== 'safe') tag.classList.add('danger');
        tag.textContent = p;
        patternsList.appendChild(tag);
      });
    } else {
      patternsTitle.style.display = 'none';
    }
  }
});
