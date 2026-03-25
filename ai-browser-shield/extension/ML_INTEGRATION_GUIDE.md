# 🚀 ML Integration - Setup & Testing Guide

## ✅ Files Created

### Backend
- ✅ `backend/api/app.py` - Flask API with ML model
- ✅ `backend/api/test_api.py` - API testing script
- ✅ `backend/api/requirements.txt` - Dependencies

### Extension
- ✅ `extension/src/api/mlAnalysis.ts` - ML API client
- ✅ `extension/src/content/mlIntegration.ts` - Gmail integration
- ✅ `extension/src/content/warningBanner.ts` - Warning UI component
- ✅ `extension/src/utils/riskColors.ts` - Color system
- ✅ `extension/src/content/index.ts` - Updated to load ML integration

---

## 🎯 Complete Setup (5 Minutes)

### Step 1: Backend is Already Running ✅

Your Flask server is running at:
- `http://localhost:5000` (Local)
- `http://10.100.25.80:5000` (Network)

Keep this terminal open!

---

### Step 2: Build Extension

Open a **new terminal**:

```bash
cd C:\Users\SOMESHWAR JOSHI\OneDrive\Desktop\Novus\ALS-Extension\ai-browser-shield\extension

# Install dependencies (if not already done)
npm install

# Build extension
npm run build
```

**Expected output:**
```
vite v5.x.x building for production...
✓ built in 3.45s
dist/
  └─ manifest.json
  └─ content.js
  └─ background.js
  └─ popup.html
```

---

### Step 3: Load Extension in Chrome

1. Open Chrome
2. Go to `chrome://extensions`
3. Enable **"Developer mode"** (top-right toggle)
4. Click **"Load unpacked"**
5. Navigate to: `C:\Users\SOMESHWAR JOSHI\OneDrive\Desktop\Novus\ALS-Extension\ai-browser-shield\extension\dist`
6. Click **"Select Folder"**

**Expected:** Extension icon appears in Chrome toolbar

---

### Step 4: Test on Gmail

1. Open Gmail: https://mail.google.com
2. Open **any email**
3. Wait **1-2 seconds**

**Expected Results:**

#### For Phishing Email (Risk > 50):
- 🚨 Red/Orange banner appears at top
- Shows risk score (e.g., "85/100")
- Click "Show Details" → Explanation expands
- All features working!

#### For Safe Email (Risk < 30):
- ✅ Small green "Email appears safe" badge (top-right)
- Fades away after 3 seconds
- No intrusive warning

---

## 🧪 Testing Checklist

### Backend Tests
```bash
# Test 1: Health check
curl http://localhost:5000/health

# Expected: {"status": "ok", ...}
```

```bash
# Test 2: Analyze phishing email
curl -X POST http://localhost:5000/analyze-email ^
  -H "Content-Type: application/json" ^
  -d "{\"text\": \"URGENT! Click: http://192.168.1.1\", \"sender\": \"scam@phish.xyz\", \"subject\": \"Alert\"}"

# Expected: {"risk_score": 85-95, "label": "phishing", ...}
```

### Extension Tests

1. **Open Chrome DevTools** (F12) → **Console** tab

2. **Check ML Integration Loaded:**
   ```javascript
   __mlIntegration
   // Expected: Object with analyzeCurrentEmail, extractEmailFromGmail, etc.
   ```

3. **Check Backend Connection:**
   ```javascript
   await __mlIntegration.checkHealth()
   // Expected: true (if backend running)
   ```

4. **Manual Analysis:**
   ```javascript
   await __mlIntegration.analyzeCurrentEmail()
   // Should show warning banner
   ```

5. **Check Console Logs:**
   - Look for: `[ML Integration] ✅ ML backend is healthy`
   - Look for: `[ML Integration] Analysis complete: {risk_score: ...}`

---

## 🎨 Visual Behavior Guide

### Risk Levels & Colors

| Risk Score | Level | Color | Banner Style |
|------------|-------|-------|--------------|
| 80-100 | 🚨 CRITICAL | Red | Full banner + "Block Links" button |
| 60-79 | ⚠️ HIGH | Orange | Full banner with warning |
| 30-59 | ⚡ MEDIUM | Yellow | Full banner, cautionary |
| 0-29 | ✅ SAFE | Green | Minimal badge only |

### UI Components

#### Loading State (while analyzing)
```
┌─────────────────────────────────────────┐
│ 🔍 Analyzing email for phishing...     │
└─────────────────────────────────────────┘
```

#### High Risk Banner
```
┌─────────────────────────────────────────────────────────┐
│ 🚨 CRITICAL Risk - Score: 92/100                        │
│ ⚠️ This email may be a phishing attempt - Be cautious  │
│                                    [Show Details ▼]     │
│                                    [🛡️ Block Links]     │
└─────────────────────────────────────────────────────────┘
```

#### Expanded Details
```
┌─────────────────────────────────────────────────────────┐
│ 🚩 Why This Is Suspicious:                              │
│   • Website link looks fake or untrustworthy            │
│   • Creates fake urgency to make you panic              │
│                                                          │
│ ⚡ What Could Happen If You Click:                      │
│   • Your passwords could be stolen                      │
│   • Malware could infect your device                    │
│                                                          │
│ ✅ What You Should Do:                                  │
│   ✓ Delete this email immediately                       │
│   ✓ Report as spam/phishing                            │
│   ✗ Never share OTP or passwords                        │
└─────────────────────────────────────────────────────────┘
```

#### Safe Badge (low risk)
```
     ┌──────────────────────┐
     │ ✅ Email appears safe │
     └──────────────────────┘
           (fades after 3s)
```

---

## 🔍 Debugging

### Problem 1: Banner Not Appearing

**Check:**
```javascript
// Open Console (F12)
// Look for these logs:
[ML Integration] Initializing...
[ML Integration] ✅ ML backend is healthy
[ML Integration] New email detected: xxxxx
[ML Integration] Analyzing email: {sender: ..., subject: ...}
[ML Integration] Analysis complete: {risk_score: 85, ...}
```

**If missing logs:**
- Extension not loaded? Check `chrome://extensions`
- On Gmail? Must be on `mail.google.com`
- Email opened? Check URL has `#inbox/message-id`

---

### Problem 2: "ML backend not responding"

**Console shows:**
```
[ML Integration] ⚠️ ML backend not responding at http://localhost:5000
```

**Fix:**
- Check Flask terminal - is server running?
- Visit http://localhost:5000/health in browser
- If down, restart: `python app.py`

---

### Problem 3: CORS Error

**Console shows:**
```
Access to fetch at 'http://localhost:5000' from origin 'https://mail.google.com'
has been blocked by CORS policy
```

**Fix:**
Already configured in Flask with `CORS(app)`

If still seeing error, check `backend/api/app.py` line 8:
```python
from flask_cors import CORS
CORS(app)  # This line must be present
```

---

### Problem 4: Extension Build Fails

**Error:** `Cannot find module 'vite'`

**Fix:**
```bash
cd extension
npm install
npm run build
```

---

## 🎯 Performance Metrics

Monitor in Console:

```javascript
// Analysis timing
[ML Integration] Analysis complete: {
  risk_score: 92,
  label: "phishing",
  duration: "287ms"  // ← Should be < 500ms
}
```

**Target Performance:**
- Backend API: < 250ms
- Network: < 50ms (localhost)
- UI Render: < 50ms
- **Total:** < 400ms ✅

---

## 📊 Test with Real Emails

### Test Email 1: Phishing (High Risk)

**Create a test email with:**
- Subject: "URGENT: Account Suspended"
- Sender: "security@hdfc-verify.xyz"
- Body: "Click here immediately: http://192.168.1.1/verify"

**Expected:**
- Risk Score: 85-95
- Label: phishing
- Red banner with "CRITICAL" warning

---

### Test Email 2: Legitimate (Low Risk)

**Open any normal email:**
- From: company email or friend
- Subject: normal text
- No urgency, no suspicious links

**Expected:**
- Risk Score: 10-25
- Label: legitimate
- Small green badge only

---

## 🎬 Demo Mode

For showing judges:

1. **Start Backend:**
   ```bash
   python backend/api/app.py
   ```

2. **Open test email** (prepare in advance)

3. **Show features:**
   - ✅ Fast detection (<500ms)
   - ✅ Clear warning banner
   - ✅ Detailed explanation (click "Show Details")
   - ✅ Link blocking (click "Block Links")
   - ✅ Risk score visualization

4. **Show Console:**
   ```javascript
   __mlIntegration.checkHealth()
   // Proves backend is connected
   ```

---

## ✅ Success Criteria

Your integration is working if:

- [x] Backend running on port 5000
- [x] Extension built and loaded
- [x] Console shows ML backend healthy
- [x] Opening email triggers analysis
- [x] Banner appears within 1-2 seconds
- [x] Colors match risk level
- [x] "Show Details" expands explanation
- [x] Response time < 500ms

---

## 🎉 You're Ready!

**Quick Start Command:**
```bash
# Terminal 1: Backend (already running ✅)
# Terminal 2: Build extension
cd extension && npm run build

# Then load in Chrome and test on Gmail!
```

**Everything is integrated and ready for demo!** 🚀
