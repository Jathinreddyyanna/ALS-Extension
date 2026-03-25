import 'dotenv/config';
import { bool, cleanEnv, num, str } from 'envalid';

export const env = cleanEnv(process.env, {
  NODE_ENV: str({ choices: ['development', 'production', 'test'], default: 'development' }),
  PORT: num({ default: 3001 }),
  DATABASE_URL: str(),
  DIRECT_URL: str(),
  REDIS_URL: str({ default: 'redis://localhost:6379' }),
  GEMINI_API_KEY: str({ default: '' }),
  SAFE_BROWSING_API_KEY: str({ default: '' }),
  VIRUSTOTAL_API_KEY: str({ default: '' }),
  PHISHTANK_API_KEY: str({ default: '' }),
  ALLOWED_ORIGINS: str(),
  API_KEY: str(),
  ADMIN_KEY: str({ default: '' }),
  REQUEST_SIGNATURE_SECRET: str({ default: '' }),
  DAILY_SALT_SECRET: str(),
  GEMINI_MODEL: str({ default: 'gemini-flash-lite-latest' }),
  GEMINI_TIMEOUT_MS: num({ default: 12000 }),
  FASTAPI_BACKEND_URL: str({ default: 'http://127.0.0.1:8000' }),
  FASTAPI_TIMEOUT_MS: num({ default: 3000 }),
  PROVIDER_TIMEOUT_MS: num({ default: 1500 }),
  MAX_URL_LENGTH: num({ default: 2048 }),
  ENABLE_FILE_SCAN: bool({ default: true }),
  SCAN_CACHE_TTL_LOW: num({ default: 3600 }),
  SCAN_CACHE_TTL_HIGH: num({ default: 300 })
});

export const allowedOrigins = env.ALLOWED_ORIGINS.split(',').map((value) => value.trim()).filter(Boolean);
export const isProduction = env.NODE_ENV === 'production';
