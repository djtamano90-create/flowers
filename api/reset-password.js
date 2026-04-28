
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { token, password } = req.body;

  if (!token || !password) {
    return res.status(400).json({ error: 'חסרים פרטים' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'הסיסמה חייבת להכיל לפחות 8 תווים' });
  }

  const tokenKey = `reset:${token}`;
  const email = await redis.get(tokenKey);

  if (!email) {
    return res.status(410).json({ error: 'הקישור פג תוקף או אינו תקין' });
  }

  const emailKey = `user:${email}`;
  const raw = await redis.get(emailKey);
  if (!raw) return res.status(404).json({ error: 'משתמש לא נמצא' });

  const user = JSON.parse(raw);
  user.pwHash = Buffer.from(password).toString('base64');
  await redis.set(emailKey, JSON.stringify(user));

  // Delete token so it can't be reused
  await redis.del(tokenKey);

  return res.status(200).json({ ok: true });
}
