# 🏗️ AI Browser Shield - Complete System Architecture

## Two Detection Systems Running in Parallel

### 1️⃣ OLD SYSTEM - Background Worker Detection
**Files:**
- `src/content/emailExtractor.ts` - Detects email opens, sends to background
- `background/index.ts` - Analyzes email via local heuristics
- Creates: Blue/yellow/orange highlighting on subject + risk banner below

**Flow:**
```
Gmail Email Opens 
  → emailExtractor.ts detects DOM change
  → Extracts text, sender
  → Sends to background worker via chrome.runtime.sendMessage()
  → Background analyzes via emailScorer.ts, urlScorer.ts
  → Returns risk_score, riskLabel
  → emailExtractor.ts receives message
  → Calls highlightSubject() and creates abs-gmail-risk-banner
```

**Output:**
- ✅ Colored subject header
- ✅ Risk banner with "⚠ AI Browser Shield" + Score below subject

**Pros:**
- Works completely offline
- No API dependency
- Analyzes text + URLs with heuristics

**Cons:**
- Rule-based (misses sophisticated attacks)
- No ML-based pattern recognition

---

### 2️⃣ NEW SYSTEM - ML-Based Detection  
**Files:**
- `src/content/mlIntegration.ts` - Detects emails, calls ML API
- `src/api/mlAnalysis.ts` - Connects to http://localhost:5000
- `src/content/warningBanner.ts` - Creates full-featured banner
- Creates: Smart banner at TOP of page with details + actions

**Flow:**
```
Gmail Email Opens
  → mlIntegration.ts detects email via URL hash change
  → Waits 800ms for email to load
  → Extracts: text, sender, subject
  → Calls http://localhost:5000/analyze-email
  → ML backend classifies email + extracts features
  → Returns: risk_score, risk_level, detected_features, explanation
  → mlIntegration.ts receives result
  → If risk < 30 → showSafeBadge() (top-right green badge)
  → If risk >= 30 → displayWarningBanner() (top-of-page colored banner)
```

**Output:**
- ✅ Safe badge (top-right, auto-disappears)
- ✅ Warning banner (top-of-page, full details, buttons)

**Pros:**
- ML-powered classification
- Detects complex phishing patterns
- Provides human-friendly explanations
- Shows detected features (money_signal, urgent_language, etc)
- Can block links in critical emails

**Cons:**
- Requires Flask backend running
- Depends on ML model accuracy
- Slower (~200-500ms)

---

## 🔍 Current State

### What You See on Screen:
1. **Subject line colored** (green/yellow/orange) - from OLD system
2. **"AI Browser Shield" box below subject** with risk score - from OLD system
3. **Possible green badge top-right** that disappears - from NEW system (if risk < 30)
4. **Top-of-page banner** - from NEW system (if risk >= 30)

### The Problem:
- Both systems analyze **independently**
- OLD system result shows immediately (heuristics)
- NEW system result shows after API call (~500ms delay)
- They might show **different risk scores** because they use different algorithms!

---

## 🎯 Recommendation for Hackathon Demo

### Option 1: Use Only OLD System (Fast & Offline)
- Disable mlIntegration
- Keep emailExtractor + background worker
- ✅ No backend needed
- ✅ Instant analysis
- ❌ Limited accuracy

### Option 2: Use Only NEW System (ML-Powered)
- Disable emailExtractor highlighting
- Keep mlIntegration + Flask backend
- ✅ Better accuracy with ML
- ✅ More impressive demo
- ❌ Requires backend + loading time

### Option 3: Use Both (Current State)
- Both systems run in parallel
- Show heuristic result immediately
- Show ML result after 500ms
- ❌ Confusing UX (two different banners)
- ✅ Demonstrates both approaches

---

## 🧪 Testing Checklist

- [ ] Check if `/health` returns 200 (backend == running)
- [ ] Share a test email and note what BOTH systems return
- [ ] Check console for `[ML Integration]` logs
- [ ] Check if `#phishing-detection-banner` exists in DOM
- [ ] Check if `#abs-gmail-risk-banner` exists in DOM
- [ ] Compare risk scores: OLD vs NEW

---

## 📝 Next Steps

1. Decide: Use oldystem OR new system OR both?
2. If merging: Use ONE unified banner showing BOTH results
3. Rebuild + reload extension
4. Test with phishing + legitimate emails
