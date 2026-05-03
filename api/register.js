import bcrypt from 'bcryptjs';
import { redis, setCors, rateLimit, getIp, sanitize, isValidEmail, isValidPassword } from './_security.js';

export default async function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const ip = getIp(req);

  // Rate limit: max 5 registrations per IP per hour
  const blocked = await rateLimit(`rl:register:${ip}`, 5, 3600);
  if (blocked) {
    return res.status(429).json({ error: 'יותר מדי ניסיונות — נסה שוב עוד שעה' });
  }

  // Sanitize inputs
  const fname    = sanitize(req.body?.fname, 50);
  const lname    = sanitize(req.body?.lname, 50);
  const dob      = sanitize(req.body?.dob, 10);
  const email    = sanitize(req.body?.email, 254).toLowerCase();
  const street   = sanitize(req.body?.street, 100);
  const city     = sanitize(req.body?.city, 50);
  const zip      = sanitize(req.body?.zip, 10);
  const password = req.body?.password;

  // Validate required fields
  if (!fname || !lname || !dob || !email || !street || !city || !password) {
    return res.status(400).json({ error: 'נא למלא את כל השדות' });
  }
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'כתובת מייל אינה תקינה' });
  }
  if (!isValidPassword(password)) {
    return res.status(400).json({ error: 'הסיסמה חייבת להכיל בין 8 ל-128 תווים' });
  }

  // Validate DOB
  const dobDate = new Date(dob);
  if (isNaN(dobDate.getTime())) {
    return res.status(400).json({ error: 'תאריך לידה אינו תקין' });
  }
  const age = (Date.now() - dobDate.getTime()) / (1000 * 60 * 60 * 24 * 365.25);
  if (age < 18) {
    return res.status(400).json({ error: 'יש להיות מעל גיל 18' });
  }

  // Check duplicate email
  const emailKey = `user:${email}`;
  const existing = await redis.get(emailKey);
  if (existing) {
    return res.status(409).json({ error: 'כתובת המייל כבר רשומה במערכת' });
  }

  // Hash password with bcrypt (cost factor 12)
  const pwHash = await bcrypt.hash(password, 12);

  const user = { fname, lname, dob, email, street, city, zip, pwHash, createdAt: new Date().toISOString() };
  await redis.set(emailKey, JSON.stringify(user));

  return res.status(200).json({ ok: true, fname });
}
