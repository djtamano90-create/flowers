import bcrypt from 'bcryptjs';
import { redis, setCors, rateLimit, getIp, sanitize, isValidEmail, isValidPassword } from './_security.js';

export default async function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const ip = getIp(req);

  // Rate limit: max 10 login attempts per IP per 15 minutes
  const ipBlocked = await rateLimit(`rl:login:ip:${ip}`, 10, 900);
  if (ipBlocked) {
    return res.status(429).json({ error: 'יותר מדי ניסיונות כניסה — נסה שוב עוד 15 דקות' });
  }

  const email    = sanitize(req.body?.email, 254).toLowerCase();
  const password = req.body?.password;

  if (!email || !password) {
    return res.status(400).json({ error: 'נא למלא את כל השדות' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'כתובת מייל אינה תקינה' });
  }
  if (!isValidPassword(password)) {
    return res.status(401).json({ error: 'מייל או סיסמה שגויים' });
  }

  // Rate limit per email: max 5 attempts per 15 minutes
  const emailBlocked = await rateLimit(`rl:login:email:${email}`, 5, 900);
  if (emailBlocked) {
    return res.status(429).json({ error: 'חשבון זה ננעל זמנית — נסה שוב עוד 15 דקות' });
  }

  const raw = await redis.get(`user:${email}`);

  // Always use bcrypt.compare to prevent timing attacks (even if user not found)
  const dummyHash = '$2a$12$dummyhashfortimingattackprevention123456789012345678';
  const pwHash = raw ? JSON.parse(raw).pwHash : dummyHash;
  const match = await bcrypt.compare(password, pwHash);

  if (!raw || !match) {
    // Generic error — don't reveal if email exists
    return res.status(401).json({ error: 'מייל או סיסמה שגויים' });
  }

  const user = JSON.parse(raw);
  return res.status(200).json({ ok: true, fname: user.fname, email: user.email });
}
