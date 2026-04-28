import Redis from 'ioredis';

const redis = new Redis(process.env.REDIS_URL);

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { fname, lname, dob, email, street, city, zip, password } = req.body;

  // Validate
  if (!fname || !lname || !dob || !email || !street || !city || !password) {
    return res.status(400).json({ error: 'נא למלא את כל השדות' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'הסיסמה חייבת להכיל לפחות 8 תווים' });
  }

  const emailKey = `user:${email.toLowerCase()}`;

  // Check if email already exists
  const existing = await redis.get(emailKey);
  if (existing) {
    return res.status(409).json({ error: 'כתובת המייל כבר רשומה במערכת' });
  }

  // Hash password (simple base64 — in production use bcrypt)
  const pwHash = Buffer.from(password).toString('base64');

  const user = {
    fname, lname, dob,
    email: email.toLowerCase(),
    street, city, zip,
    pwHash,
    createdAt: new Date().toISOString()
  };

  await redis.set(emailKey, JSON.stringify(user));

  return res.status(200).json({ ok: true, fname });
}
