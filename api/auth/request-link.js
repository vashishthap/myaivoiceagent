// POST /api/auth/request-link
// Body: { email }
// Behaviour:
//   - Reject non-allowlisted emails with the SAME response shape as success
//     (no email enumeration: attacker can't tell which addresses are admins)
//   - For allowlisted emails: send a magic link via Resend (10-min TTL)
//   - Always reply 200 within ~1s
//
// Magic link points to /api/auth/verify?token=<token> which sets the session cookie.

import { createToken, isAllowed, isValidEmail, MAGIC_LINK_TTL, getSiteUrl } from './_lib.js'

export default async function handler(req, res) {
  const SITE = getSiteUrl(req)

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST')
    return res.status(405).json({ error: 'Method not allowed' })
  }

  const email = (req.body?.email || '').trim().toLowerCase()
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' })
  }

  // Constant-time response: always look like we sent a link, even if not allowlisted.
  // Attacker can't probe the allowlist.
  if (!isAllowed(email)) {
    // Small artificial delay to keep timing roughly consistent with the success path.
    await new Promise((r) => setTimeout(r, 400))
    return res.status(200).json({ ok: true })
  }

  if (!process.env.RESEND_API_KEY) {
    console.error('Magic link blocked: RESEND_API_KEY not configured')
    return res.status(500).json({ error: 'Server misconfiguration' })
  }
  if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 16) {
    console.error('Magic link blocked: JWT_SECRET not set or too short')
    return res.status(500).json({ error: 'Server misconfiguration' })
  }

  const token = createToken(email, MAGIC_LINK_TTL)
  const link = `${SITE}/api/auth/verify?token=${encodeURIComponent(token)}`

  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'myaivoiceagent.co <noreply@myaivoiceagent.co>',
        to: [email],
        subject: 'Sign in to myaivoiceagent.co admin',
        html: `
          <div style="font-family:-apple-system,Segoe UI,Inter,sans-serif;max-width:520px;margin:0 auto;padding:32px 24px;color:#0f172a;">
            <h1 style="font-size:22px;margin:0 0 8px;">Sign in to myaivoiceagent.co admin</h1>
            <p style="font-size:15px;line-height:1.6;color:#334155;">
              Click the button below to sign in to your SEO dashboard. The link is valid for 10 minutes.
            </p>
            <p style="margin:28px 0;">
              <a href="${link}" style="display:inline-block;background:#0F172A;color:#fff;text-decoration:none;padding:12px 22px;border-radius:8px;font-weight:600;">Sign in</a>
            </p>
            <p style="font-size:13px;color:#64748B;line-height:1.6;">
              Or paste this link into your browser:<br>
              <span style="word-break:break-all;">${link}</span>
            </p>
            <hr style="border:0;border-top:1px solid #E2E8F0;margin:28px 0;">
            <p style="font-size:12px;color:#94A3B8;line-height:1.6;">
              You're receiving this because someone (hopefully you) requested a sign-in link for the
              myaivoiceagent.co admin dashboard. If it wasn't you, ignore this email — the link expires
              in 10 minutes and grants no access without it.
            </p>
          </div>
        `,
      }),
    })

    if (!r.ok) {
      const data = await r.json().catch(() => ({}))
      console.error('Resend send failed:', data)
      return res.status(500).json({ error: 'Could not send magic link. Try again shortly.' })
    }

    return res.status(200).json({ ok: true })
  } catch (err) {
    console.error('Magic link send error:', err)
    return res.status(500).json({ error: 'Could not send magic link. Try again shortly.' })
  }
}
