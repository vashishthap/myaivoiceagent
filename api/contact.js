// api/contact.js — Vercel serverless function
// Receives form data and sends an email via Resend API.
// Requires: RESEND_API_KEY environment variable set in Vercel project settings.
 
export default async function handler(req, res) {
  // Only accept POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
 
  const { name, business, email, phone, industry, message } = req.body;
 
  // Basic validation
  if (!name || !business || !email) {
    return res.status(400).json({ error: 'Missing required fields: name, business, email' });
  }
 
  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        // Use onboarding@resend.dev for testing until myaivoiceagent.co domain is verified in Resend.
        // Once domain is verified, change to: 'Demo Form <noreply@myaivoiceagent.co>'
        from: 'Demo Form <onboarding@resend.dev>',
        to: ['ceo@nothingbutvalue.com'],
        reply_to: email,
        subject: `Demo Request — ${business}`,
        html: `
          <h2 style="font-family:sans-serif;color:#0f172a;">New Demo Request</h2>
          <table style="font-family:sans-serif;font-size:15px;line-height:1.8;border-collapse:collapse;">
            <tr><td style="padding:4px 16px 4px 0;color:#64748b;font-weight:600;">Name</td><td>${escapeHtml(name)}</td></tr>
            <tr><td style="padding:4px 16px 4px 0;color:#64748b;font-weight:600;">Business</td><td>${escapeHtml(business)}</td></tr>
            <tr><td style="padding:4px 16px 4px 0;color:#64748b;font-weight:600;">Email</td><td><a href="mailto:${escapeHtml(email)}">${escapeHtml(email)}</a></td></tr>
            <tr><td style="padding:4px 16px 4px 0;color:#64748b;font-weight:600;">Phone</td><td>${escapeHtml(phone || '—')}</td></tr>
            <tr><td style="padding:4px 16px 4px 0;color:#64748b;font-weight:600;">Industry</td><td>${escapeHtml(industry || '—')}</td></tr>
            <tr><td style="padding:4px 16px 4px 0;color:#64748b;font-weight:600;">Challenge</td><td>${escapeHtml(message || '—')}</td></tr>
          </table>
          <hr style="margin:24px 0;border:none;border-top:1px solid #e2e8f0;">
          <p style="font-family:sans-serif;font-size:13px;color:#94a3b8;">Sent from myaivoiceagent.co demo form</p>
        `,
      }),
    });
 
    if (!response.ok) {
      const errorData = await response.json();
      console.error('Resend API error:', errorData);
      throw new Error(errorData.message || 'Resend API returned an error');
    }
 
    return res.status(200).json({ success: true });
 
  } catch (err) {
    console.error('Contact form error:', err);
    return res.status(500).json({ error: 'Failed to send email. Please try again.' });
  }
}
 
// Prevent XSS in email body
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
 
