import bcrypt from 'bcryptjs';
import { redis, setCors, rateLimit, getIp, isValidPassword } from './_security.js';

export default async function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const ip = getIp(req);

  // Rate limit: max 5 attempts per IP per 15 minutes
  const blocked = await rateLimit(`rl:resetpw:${ip}`, 5, 900);
  if (blocked) {
    return res.status(429).json({ error: 'יותר מדי ניסיונות — נסה שוב מאוחר יותר' });
  }

  const { token, password } = req.body;

  // Validate token format (should be 64 hex chars)
  if (!token || !/^[a-f0-9]{64}$/.test(token)) {
    return res.status(400).json({ error: 'קישור לא תקין' });
  }
  if (!isValidPassword(password)) {
    return res.status(400).json({ error: 'הסיסמה חייבת להכיל בין 8 ל-128 תווים' });
  }

  const tokenKey = `reset:${token}`;
  const email = await redis.get(tokenKey);

  if (!email) {
    return res.status(410).json({ error: 'הקישור פג תוקף או אינו תקין' });
  }

  const raw = await redis.get(`user:${email}`);
  if (!raw) return res.status(404).json({ error: 'משתמש לא נמצא' });

  const user = JSON.parse(raw);

  // Hash new password
  user.pwHash = await bcrypt.hash(password, 12);
  user.passwordChangedAt = new Date().toISOString();

  await redis.set(`user:${email}`, JSON.stringify(user));

  // Delete token immediately — cannot be reused
  await redis.del(tokenKey);

  return res.status(200).json({ ok: true });
}
