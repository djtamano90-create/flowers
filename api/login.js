
import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'נא למלא את כל השדות' });
  }

  const emailKey = `user:${email.toLowerCase()}`;
  const raw = await redis.get(emailKey);

  if (!raw) {
    return res.status(404).json({ error: 'המייל אינו רשום במערכת' });
  }

  const user = JSON.parse(raw);
  const pwHash = Buffer.from(password).toString('base64');

  if (user.pwHash !== pwHash) {
    return res.status(401).json({ error: 'סיסמה שגויה' });
  }

  return res.status(200).json({
    ok: true,
    fname: user.fname,
    email: user.email
  });
}
