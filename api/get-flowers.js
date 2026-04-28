import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { email, all } = req.query;

  // Get all flowers (for catalog)
  if (all === 'true') {
    const raw = await redis.get('flowers:all');
    const flowers = raw ? JSON.parse(raw) : [];
    return res.status(200).json({ flowers });
  }

  // Get user's flowers
  if (!email) return res.status(400).json({ error: 'Missing email' });
  const raw = await redis.get(`flowers:${email.toLowerCase()}`);
  const flowers = raw ? JSON.parse(raw) : [];
  return res.status(200).json({ flowers });
}
