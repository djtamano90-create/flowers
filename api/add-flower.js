import { redis, setCors, rateLimit, getIp, sanitize, isValidEmail } from './_security.js';

export default async function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const ip = getIp(req);

  // Rate limit: max 10 flowers per IP per hour
  const blocked = await rateLimit(`rl:addflower:${ip}`, 10, 3600);
  if (blocked) {
    return res.status(429).json({ error: 'יותר מדי הוספות — נסה שוב עוד שעה' });
  }

  const email   = sanitize(req.body?.email, 254).toLowerCase();
  const name    = sanitize(req.body?.name, 100);
  const desc    = sanitize(req.body?.desc, 300);
  const price   = sanitize(req.body?.price, 50);
  const emoji   = sanitize(req.body?.emoji, 5) || '🌸';
  const details = sanitize(req.body?.details, 1000);
  const img     = req.body?.img;

  // Validate
  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ error: 'מייל לא תקין' });
  }
  if (!name || !desc || !price) {
    return res.status(400).json({ error: 'חסרים פרטים' });
  }

  // Validate image — must be Cloudinary URL or data URL
  if (!img || typeof img !== 'string') {
    return res.status(400).json({ error: 'תמונה חסרה' });
  }
  const isCloudinary = img.includes('cloudinary.com');
  const isDataUrl    = img.startsWith('data:image/');
  if (!isCloudinary && !isDataUrl) {
    return res.status(400).json({ error: 'מקור תמונה לא מורשה' });
  }
  if (img.length > 2_000_000) {
    return res.status(400).json({ error: 'התמונה גדולה מדי' });
  }

  // Verify user exists
  const userRaw = await redis.get(`user:${email}`);
  if (!userRaw) return res.status(404).json({ error: 'משתמש לא נמצא' });

  const flower = {
    id: Date.now().toString(),
    name, desc, price, emoji, details,
    img,
    tags: ['colorful'],
    addedBy: email,
    createdAt: new Date().toISOString()
  };

  // Save to user's flower list
  const userFlowersKey = `flowers:${email}`;
  const existing = await redis.get(userFlowersKey);
  const userFlowers = existing ? JSON.parse(existing) : [];
  userFlowers.unshift(flower);
  await redis.set(userFlowersKey, JSON.stringify(userFlowers));

  // Save to global catalog
  const globalRaw = await redis.get('flowers:all');
  const globalFlowers = globalRaw ? JSON.parse(globalRaw) : [];
  globalFlowers.unshift(flower);
  await redis.set('flowers:all', JSON.stringify(globalFlowers));

  return res.status(200).json({ ok: true, flower });
}
