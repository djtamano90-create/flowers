import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

export default async function handler(req, res) {
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const { email } = req.query;
  if (!email) return res.status(400).json({ error: 'Missing email' });

  const raw = await redis.get(`user:${email.toLowerCase()}`);
  if (!raw) return res.status(404).json({ error: 'User not found' });

  const user = JSON.parse(raw);
  // Remove password before sending
  delete user.pwHash;

  return res.status(200).json({ user });
}
