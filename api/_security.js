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
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
}

/* ── RATE LIMITING ── */
export async function rateLimit(key, max, windowSec) {
  const current = await redis.incr(key);
  if (current === 1) await redis.expire(key, windowSec);
  return current > max;
}

export function getIp(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

/* ── SANITIZATION ── */
export function sanitize(str, maxLen = 200) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLen).replace(/[<>'"`;]/g, '');
}

/* ── FIELD VALIDATORS ── */

export function isValidEmail(email) {
  // RFC-compliant, no consecutive dots, no suspicious chars
  if (typeof email !== 'string') return false;
  if (email.length > 254) return false;
  if (/\.\./.test(email)) return false;
  return /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(email);
}

export function isValidPassword(pw) {
  if (typeof pw !== 'string') return false;
  if (pw.length < 8 || pw.length > 128) return false;
  return true;
}

export function isStrongPassword(pw) {
  if (!isValidPassword(pw)) return false;
  const hasUpper   = /[A-Z]/.test(pw);
  const hasLower   = /[a-z]/.test(pw);
  const hasDigit   = /[0-9]/.test(pw);
  return hasUpper && hasLower && hasDigit;
}

// Hebrew + English letters, spaces, hyphens, apostrophes only
export function isValidName(str) {
  if (!str || str.length < 2 || str.length > 50) return false;
  return /^[\u0590-\u05FFa-zA-Z\s\-']+$/.test(str);
}

// Hebrew + English letters and spaces only — no numbers
export function isValidCity(str) {
  if (!str || str.length < 2 || str.length > 50) return false;
  return /^[\u0590-\u05FFa-zA-Z\s\-']+$/.test(str);
}

// Israeli ZIP: 5 or 7 digits only
export function isValidZip(str) {
  if (!str) return true; // zip is optional
  return /^\d{5}(\d{2})?$/.test(str.replace(/\s/g, ''));
}

// Street: letters (Hebrew/English), digits, spaces, hyphens
export function isValidStreet(str) {
  if (!str || str.length < 2 || str.length > 100) return false;
  return /^[\u0590-\u05FFa-zA-Z0-9\s\-'.,"]+$/.test(str);
}

// Date of birth: between 1900 and today, age 18+
export function isValidDob(str) {
  if (!str) return false;
  const d = new Date(str);
  if (isNaN(d.getTime())) return false;
  if (d.getFullYear() < 1900) return false;
  if (d > new Date()) return false;
  const age = (Date.now() - d.getTime()) / (1000 * 60 * 60 * 24 * 365.25);
  return age >= 18;
}

// Flower name/desc: no HTML, no script injection
export function isValidFlowerText(str, maxLen = 300) {
  if (!str || str.trim().length < 2) return false;
  if (str.length > maxLen) return false;
  return !/[<>{}]/.test(str);
}

// Price: numbers, currency symbols, Hebrew letters, spaces
export function isValidPrice(str) {
  if (!str || str.length > 50) return false;
  return /^[\u0590-\u05FF\d\s₪$€.,\-/]+$/.test(str);
}

/* ── HONEYPOT CHECK (anti-bot) ── */
export function isBotRequest(body) {
  // If honeypot field "website" is filled — it's a bot
  return !!body?.website;
}

export { redis };
