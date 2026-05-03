import { Resend } from 'resend';
import { redis, setCors, rateLimit, getIp, sanitize, isValidEmail } from './_security.js';

const resend = new Resend(process.env.RESEND_API_KEY);
const TOKEN_TTL_SECONDS = 3 * 60 * 60; // 3 hours

export default async function handler(req, res) {
  setCors(res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const ip = getIp(req);

  // Rate limit: max 3 reset requests per IP per hour
  const blocked = await rateLimit(`rl:reset:${ip}`, 3, 3600);
  if (blocked) {
    return res.status(429).json({ error: 'יותר מדי בקשות — נסה שוב עוד שעה' });
  }

  const email = sanitize(req.body?.email, 254).toLowerCase();

  if (!email || !isValidEmail(email)) {
    return res.status(400).json({ error: 'נא להזין כתובת מייל תקינה' });
  }

  // Rate limit per email: max 2 per hour
  const emailBlocked = await rateLimit(`rl:reset:email:${email}`, 2, 3600);
  if (emailBlocked) {
    return res.status(429).json({ error: 'בקשה נשלחה לאחרונה — בדוק את תיבת הדואר שלך' });
  }

  const raw = await redis.get(`user:${email}`);

  // Always return OK — don't reveal if email exists (security best practice)
  if (!raw) return res.status(200).json({ ok: true });

  const user = JSON.parse(raw);

  // Generate cryptographically strong token using crypto module
  const { randomBytes } = await import('crypto');
  const token = randomBytes(32).toString('hex');
  const tokenKey = `reset:${token}`;

  await redis.setex(tokenKey, TOKEN_TTL_SECONDS, email);

  const baseUrl = process.env.ALLOWED_ORIGIN || `https://${req.headers.host}`;
  const resetUrl = `${baseUrl}?reset=${token}`;

  await resend.emails.send({
    from: 'פריחה <onboarding@resend.dev>',
    to: email,
    subject: 'איפוס סיסמה — פריחה',
    html: `
      <!DOCTYPE html>
      <html dir="rtl" lang="he">
      <body style="font-family: Arial, sans-serif; background: #faf6f0; padding: 40px 20px; margin: 0;">
        <div style="max-width: 480px; margin: 0 auto; background: #fff; border-radius: 16px; padding: 40px; box-shadow: 0 4px 24px rgba(44,44,44,0.1);">
          <h1 style="font-size: 1.8rem; color: #c9697a; text-align: center; margin-bottom: 8px;">פריחה 🌸</h1>
          <p style="color: #666; text-align: center; margin-bottom: 32px; font-size: 0.9rem;">חנות הפרחים החכמה</p>
          <h2 style="font-size: 1.2rem; color: #2c2c2c; margin-bottom: 12px;">שלום ${user.fname},</h2>
          <p style="color: #666; line-height: 1.7; margin-bottom: 24px;">
            קיבלנו בקשה לאיפוס הסיסמה לחשבונך.<br/>
            לחץ על הכפתור למטה כדי לבחור סיסמה חדשה.
          </p>
          <div style="text-align: center; margin: 32px 0;">
            <a href="${resetUrl}" style="background: #c9697a; color: #fff; padding: 14px 36px; border-radius: 50px; text-decoration: none; font-size: 1rem; font-weight: 500; display: inline-block;">
              ✦ איפוס סיסמה
            </a>
          </div>
          <p style="color: #aaa; font-size: 0.8rem; text-align: center; line-height: 1.6;">
            הקישור תקף ל-<strong>3 שעות</strong> בלבד.<br/>
            אם לא ביקשת לאפס סיסמה — התעלם מהודעה זו.
          </p>
          <hr style="border: none; border-top: 1px solid #f0ece6; margin: 24px 0;"/>
          <p style="color: #ccc; font-size: 0.75rem; text-align: center;">© פריחה — חנות הפרחים החכמה</p>
        </div>
      </body>
      </html>
    `
  });

  return res.status(200).json({ ok: true });
}
