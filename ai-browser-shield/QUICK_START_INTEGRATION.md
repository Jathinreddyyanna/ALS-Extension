# 🚀 QUICK START - Integration Guide

## ✅ What You Have Now

1. ✅ **ML Model** - `train_email_model.py` (trained)
2. ✅ **Explanation System** - `explain_phishing.py`
3. ✅ **Backend API** - `backend/api/app.py` (Flask)
4. ✅ **Chrome Extension** - Already built
5. ✅ **Test Suite** - `test_emails.py`
6. ✅ **Architecture Docs** - `INTEGRATION_ARCHITECTURE.md`

---

## ⚡ 5-Minute Setup

### Step 1: Start Backend API (2 minutes)

```bash
# Terminal 1 - Backend
cd ai-browser-shield/backend/api

# Install dependencies
pip install -r requirements.txt

# Start Flask server
python app.py

# ✅ Server running at http://localhost:5000
```

**Expected Output:**
```
======================================================================
EMAIL PHISHING DETECTION API
======================================================================

Starting Flask server...
API will be available at: http://localhost:5000

Endpoints:
  GET  /health          - Health check
  POST /analyze-email   - Analyze single email
  POST /batch-analyze   - Analyze multiple emails (optional)
```

---

### Step 2: Test API (1 minute)

```bash
# Terminal 2 - Testing
cd ai-browser-shield/backend/api

# Install requests
pip install requests

# Run tests
python test_api.py
```

**Expected Output:**
```
Testing /health endpoint...
Status: 200
Response: {
  "status": "ok",
  "service": "email-phishing-detection"
}

Testing phishing email detection...
Status: 200

Risk Score: 92/100
Label: phishing
Risk Level: HIGH
Confidence: 94%

✅ ALL TESTS COMPLETED
```

---

### Step 3: Update Extension Config (30 seconds)

**File:** `extension/src/api/client.ts`

```typescript
// Update API URL
export const API_BASE_URL = 'http://localhost:5000';

export async function analyzeEmail(emailData: EmailData) {
  const response = await fetch(`${API_BASE_URL}/analyze-email`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(emailData)
  });

  return await response.json();
}
```

---

### Step 4: Build & Load Extension (1 minute)

```bash
# Terminal 3 - Extension
cd ai-browser-shield/extension

# Build extension
npm run build

# Output: dist/ folder created
```

**Load in Chrome:**
1. Open `chrome://extensions`
2. Enable "Developer mode"
3. Click "Load unpacked"
4. Select `ai-browser-shield/extension/dist/`

---

### Step 5: Test Live (30 seconds)

1. Open Gmail
2. Open any email
3. Wait 1-2 seconds
4. See analysis result (banner or popup)

---

## 📝 Integration Checklist

### Backend ✅
- [ ] Flask server running on port 5000
- [ ] `/health` endpoint returns 200
- [ ] `/analyze-email` returns valid JSON
- [ ] Model loaded successfully (no errors)
- [ ] Test API with `test_api.py` passes

### Extension ✅
- [ ] Built successfully (`npm run build`)
- [ ] Loaded in Chrome extensions
- [ ] No console errors
- [ ] Can access `chrome.runtime`
- [ ] API_BASE_URL configured correctly

### Integration ✅
- [ ] Extension calls backend API
- [ ] Receives JSON response
- [ ] Displays risk score
- [ ] Shows explanation
- [ ] Response time <500ms

---

## 🔧 Common Issues & Fixes

### Issue 1: "Cannot connect to API"
**Problem:** Extension can't reach backend

**Fix:**
```typescript
// Check CORS is enabled in Flask
from flask_cors import CORS
app = Flask(__name__)
CORS(app)  # ✅ This line is critical
```

---

### Issue 2: "Model not found"
**Problem:** `email_model.pkl` doesn't exist

**Fix:**
```bash
# Train model first
cd backend/scripts
python train_email_model.py ../data/cleaned_emails.csv
```

---

### Issue 3: "Import error in Flask"
**Problem:** Can't import `classify_email`

**Fix:**
```python
# In app.py, add parent directory to path
import sys
sys.path.append('../scripts')  # ✅ Add this
from train_email_model import classify_email
```

---

### Issue 4: Extension shows no result
**Problem:** Content script not extracting email

**Debugging:**
```typescript
// Add console logs
console.log('Email extracted:', emailData);
console.log('API response:', result);

// Check if running on Gmail
if (!window.location.href.includes('mail.google.com')) {
  console.error('Not on Gmail!');
}
```

---

### Issue 5: Slow response (>2 seconds)
**Problem:** Model takes too long

**Fix:**
```python
# Load model globally (once at startup)
MODEL = load_model()  # Outside request handler

def classify_email_fast(text, sender, subject):
    return MODEL.predict(...)  # Use pre-loaded model
```

---

## 📊 Testing Strategy

### 1. Unit Tests (Backend)
```bash
# Test each component
python test_api.py
```

### 2. Integration Tests (Extension + Backend)
```bash
# Use test emails
from test_emails import TEST_EMAILS

for test in TEST_EMAILS:
    result = analyze_email(test['text'], test['sender'], test['subject'])
    print(f"{test['id']}: {result['label']}")
```

### 3. Manual Tests (Live Gmail)
- ✅ Open phishing email → Shows red warning
- ✅ Open legitimate email → Shows green or no banner
- ✅ Open Hindi phishing → Detects correctly
- ✅ Click "Show Details" → Expands explanation
- ✅ Response time <500ms

---

## 🎯 Demo Day Checklist

### 24 Hours Before
- [ ] Backend API tested thoroughly
- [ ] Extension tested on 10+ emails
- [ ] All test cases pass
- [ ] Performance <500ms verified
- [ ] Screenshots taken
- [ ] Backup plan ready

### Day Of
- [ ] Backend server started
- [ ] Extension loaded in Chrome
- [ ] Gmail logged in
- [ ] Test emails bookmarked
- [ ] Presentation ready
- [ ] Backup video recorded

### Demo Flow
1. Show architecture diagram (30s)
2. Start backend (show terminal) (15s)
3. Load extension in Chrome (15s)
4. Open phishing email → Show detection (1m)
5. Open legitimate email → Show it's safe (30s)
6. Show Hindi detection (30s)
7. Show metrics (accuracy, FPR) (30s)
8. Q&A (2m)

**Total: 5 minutes**

---

## 🚨 Backup Plans

### Plan A: Live Demo (Preferred)
- Backend + Extension both running
- Real Gmail emails
- Live detection

### Plan B: Recorded Video (If Demo Fails)
- Pre-recorded successful demo
- Voice-over explanation
- Show all features working

### Plan C: API-Only Demo (If Extension Fails)
- Just show backend API
- Use Postman/curl
- Show JSON responses
- Explain what extension would do

---

## 📈 Performance Benchmarks

### Expected Timings
| Component | Target | Acceptable | Critical |
|-----------|--------|------------|----------|
| ML Inference | <200ms | <300ms | >500ms |
| Feature Detection | <20ms | <50ms | >100ms |
| Explanation Gen | <10ms | <30ms | >50ms |
| Network Latency | <50ms | <100ms | >200ms |
| **Total UX** | **<300ms** | **<500ms** | **>1000ms** |

### Optimization Tips
1. ✅ Load model at startup (not per request)
2. ✅ Cache repeated emails (LRU cache)
3. ✅ Use gzip compression
4. ✅ Debounce extension calls
5. ✅ Show loading indicator

---

## 💡 Pro Tips

### Backend
```python
# Pre-load model for faster inference
MODEL = load_model()  # Do this ONCE at startup

# Cache results
@lru_cache(maxsize=1000)
def cached_classify(email_hash):
    ...
```

### Extension
```typescript
// Debounce API calls
let timer;
function analyzeEmail(data) {
  clearTimeout(timer);
  timer = setTimeout(() => callAPI(data), 500);
}

// Show instant feedback
displayScore({ loading: true, score: 50 });
// Then update with real score when API returns
```

### Debugging
```bash
# Backend logs
python app.py  # Shows request logs

# Extension logs
Chrome DevTools → Console → Filter by extension ID

# Network logs
Chrome DevTools → Network → Filter by "analyze-email"
```

---

## ✅ Success Criteria

Your integration is ready when:

1. ✅ Backend API responds in <300ms
2. ✅ Extension shows result in <500ms total
3. ✅ Phishing emails detected correctly (>85%)
4. ✅ Legitimate emails not flagged (<5% FPR)
5. ✅ UI is clear and actionable
6. ✅ No console errors
7. ✅ Demo flows smoothly

---

## 🎉 You're Ready!

**Files Created:**
- ✅ `backend/api/app.py` - Flask API
- ✅ `backend/api/requirements.txt` - Dependencies
- ✅ `backend/api/test_api.py` - API tests
- ✅ `INTEGRATION_ARCHITECTURE.md` - Full architecture

**Your Next Steps:**
1. Start backend: `python app.py`
2. Test API: `python test_api.py`
3. Update extension API URL
4. Build extension: `npm run build`
5. Load in Chrome
6. Test on Gmail
7. **Demo ready!** 🚀

---

**Total setup time: 5 minutes**
**Demo preparation time: 30 minutes**
**You're good to go!** ✨
