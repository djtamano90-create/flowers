import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { email, name, desc, price, emoji, details, img, tags } = req.body;

  if (!email || !name || !desc || !price || !img) {
    return res.status(400).json({ error: 'חסרים פרטים' });
  }

  // Verify user exists
  const userRaw = await redis.get(`user:${email.toLowerCase()}`);
  if (!userRaw) return res.status(404).json({ error: 'משתמש לא נמצא' });

  const flower = {
    id: Date.now().toString(),
    name,
    desc,
    price,
    emoji: emoji || '🌸',
    details: details || '',
    img,
    tags: tags || ['colorful'],
    addedBy: email.toLowerCase(),
    createdAt: new Date().toISOString()
  };

  // Save to user's flower list
  const userFlowersKey = `flowers:${email.toLowerCase()}`;
  const existing = await redis.get(userFlowersKey);
  const flowers = existing ? JSON.parse(existing) : [];
  flowers.unshift(flower);
  await redis.set(userFlowersKey, JSON.stringify(flowers));

  // Also save to global catalog
  const globalKey = 'flowers:all';
  const globalRaw = await redis.get(globalKey);
  const globalFlowers = globalRaw ? JSON.parse(globalRaw) : [];
  globalFlowers.unshift(flower);
  await redis.set(globalKey, JSON.stringify(globalFlowers));

  return res.status(200).json({ ok: true, flower });
}
