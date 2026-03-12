# 🛡️ AI Browser Shield

Real-time AI-powered browser extension for protection against phishing, malware, redirects, popup abuse, and suspicious downloads. Powered by Google Gemini AI.

---

## 🚀 Quick Start (Hackathon Setup — ~20 minutes)

### Prerequisites
- Node.js 20+
- Docker Desktop
- Chrome Browser
- Gemini API Key (get free at https://aistudio.google.com/apikey)

---

### 1. Clone & Setup

```bash
git clone <your-repo>
cd ai-browser-shield
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

---

### 2. Start Backend (with Docker)

```bash
docker-compose up -d
cd backend
npm install
npx prisma migrate dev --name init
npx prisma generate
npm run db:seed       # loads demo data
npm run dev           # starts on http://localhost:3001
```

Verify: http://localhost:3001/api/v1/health

---

### 3. Build Extension

```bash
cd extension
npm install
npm run build         # outputs to extension/dist/
```

---

### 4. Load Extension in Chrome

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked**
4. Select the `extension/dist/` folder
5. Pin the extension to your toolbar

---

### 5. Set Extension ID in Backend

After loading, copy the Extension ID from `chrome://extensions` and paste it into `backend/.env`:

```
ALLOWED_ORIGINS=chrome-extension://YOUR_EXTENSION_ID_HERE
```

Restart the backend.

---

## 📁 Project Structure

```
ai-browser-shield/
├── extension/          # Chrome MV3 Extension
│   ├── src/
│   │   ├── background/ # Service Worker
│   │   ├── content/    # Content Scripts + Overlays
│   │   ├── detection/  # URL Scorer, Redirect Tracker, Download Checker
│   │   ├── popup/      # React Popup UI
│   │   └── api/        # Backend API client
│   └── rules/          # Ad blocking rules
│
└── backend/            # Node.js + Express API
    ├── src/
    │   ├── routes/     # REST endpoints
    │   ├── services/   # Business logic
    │   ├── ai/         # Gemini AI integration
    │   ├── middleware/  # Rate limiting, validation, errors
    │   └── db/         # Prisma client + seed
    └── prisma/         # Database schema
```

---

## 🔌 API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | /api/v1/reports | Submit threat report |
| GET | /api/v1/reports/recent | Community threat feed |
| POST | /api/v1/scan/url | AI URL threat analysis |
| POST | /api/v1/scan/file | AI file safety scan |
| GET | /api/v1/domain/:domain/score | Domain risk score |
| GET | /api/v1/health | Service health check |

---

## 🗄️ Database (Supabase)

For production/deployment replace Docker Postgres with Supabase:

1. Create project at https://supabase.com
2. Copy connection strings to `.env`
3. Run `npx prisma migrate deploy`

---

## ☁️ Deploy Backend (Railway)

```bash
npm install -g @railway/cli
railway login
railway init
railway up
railway variables set GEMINI_API_KEY=your_key DATABASE_URL=your_supabase_url REDIS_URL=your_upstash_url
```

---

## 🧪 Test Threat Detection

Visit these test URLs after installing the extension:
- `http://paypa1-login.tk` — should trigger phishing warning
- `http://192.168.1.1/download.exe` — should trigger download warning
- Any site with 3+ popups — should trigger popup blocker

---

## 👥 Team Assignments

| Member | Owns |
|--------|------|
| Dev 1 | extension/src/background + extension/src/detection |
| Dev 2 | extension/src/popup + extension/src/overlay |
| Dev 3 | backend/src/routes + backend/src/services + prisma |
| Dev 4 | backend/src/ai + Docker/Railway deployment |
