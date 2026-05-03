import bcrypt from 'bcryptjs';
import {
  redis, setCors, rateLimit, getIp,
  sanitize, isValidEmail, isValidPassword, isStrongPassword,
  isValidName, isValidCity, isValidZip, isValidStreet, isValidDob,
  isBotRequest
} from './_security.js';

export default async function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const ip = getIp(req);

  // Rate limit: 5 registrations per IP per hour
  const blocked = await rateLimit(`rl:register:${ip}`, 5, 3600);
  if (blocked) {
    return res.status(429).json({ error: 'יותר מדי ניסיונות — נסה שוב עוד שעה' });
  }

  // Honeypot anti-bot check
  if (isBotRequest(req.body)) {
    return res.status(200).json({ ok: true }); // silently ignore bots
  }

  // Sanitize inputs
  const fname    = sanitize(req.body?.fname, 50);
  const lname    = sanitize(req.body?.lname, 50);
  const dob      = sanitize(req.body?.dob, 10);
  const email    = sanitize(req.body?.email, 254).toLowerCase();
  const street   = sanitize(req.body?.street, 100);
  const city     = sanitize(req.body?.city, 50);
  const zip      = sanitize(req.body?.zip, 10).replace(/\s/g, '');
  const password = req.body?.password;

  // Validate each field individually with clear error messages
  if (!isValidName(fname))
    return res.status(400).json({ error: 'שם פרטי חייב להכיל אותיות בלבד (2-50 תווים)' });

  if (!isValidName(lname))
    return res.status(400).json({ error: 'שם משפחה חייב להכיל אותיות בלבד (2-50 תווים)' });

  if (!isValidDob(dob))
    return res.status(400).json({ error: 'תאריך לידה לא תקין — יש להיות מעל גיל 18' });

  if (!isValidEmail(email))
    return res.status(400).json({ error: 'כתובת מייל אינה תקינה' });

  if (!isValidStreet(street))
    return res.status(400).json({ error: 'כתובת רחוב לא תקינה' });

  if (!isValidCity(city))
    return res.status(400).json({ error: 'שם עיר חייב להכיל אותיות בלבד (לא מספרים)' });

  if (!isValidZip(zip))
    return res.status(400).json({ error: 'מיקוד חייב להכיל 5 או 7 ספרות בלבד' });

  if (!isValidPassword(password))
    return res.status(400).json({ error: 'הסיסמה חייבת להכיל בין 8 ל-128 תווים' });

  if (!isStrongPassword(password))
    return res.status(400).json({ error: 'הסיסמה חייבת לכלול אות גדולה, אות קטנה ומספר' });

  // Check duplicate email
  const emailKey = `user:${email}`;
  const existing = await redis.get(emailKey);
  if (existing) {
    return res.status(409).json({ error: 'כתובת המייל כבר רשומה במערכת' });
  }

  // Hash password with bcrypt
  const pwHash = await bcrypt.hash(password, 12);

  const user = {
    fname, lname, dob, email, street, city, zip,
    pwHash,
    createdAt: new Date().toISOString()
  };

  await redis.set(emailKey, JSON.stringify(user));
  return res.status(200).json({ ok: true, fname });
}
