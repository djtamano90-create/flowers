import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

/* ── CORS ── */
export function setCors(res) {
  const allowed = process.env.ALLOWED_ORIGIN || 'https://flowers-two-delta.vercel.app';
  res.setHeader('Access-Control-Allow-Origin', allowed);
  res.setHeader('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
}

/* ── RATE LIMITING ── */
// key: e.g. "rl:login:1.2.3.4"
// max: max attempts, windowSec: time window in seconds
export async function rateLimit(key, max, windowSec) {
  const current = await redis.incr(key);
  if (current === 1) await redis.expire(key, windowSec);
  return current > max; // true = blocked
}

export function getIp(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

/* ── INPUT SANITIZATION ── */
export function sanitize(str, maxLen = 200) {
  if (typeof str !== 'string') return '';
  return str
    .trim()
    .slice(0, maxLen)
    .replace(/[<>]/g, ''); // strip basic HTML injection
}

export function isValidEmail(email) {
  return /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/.test(email);
}

export function isValidPassword(pw) {
  return typeof pw === 'string' && pw.length >= 8 && pw.length <= 128;
}

export { redis };
