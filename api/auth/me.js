// GET /api/auth/me
// Returns { email } if a valid session cookie exists and the email is still allowlisted,
// otherwise 401. Used by /app/index.html on load to decide whether to render or redirect.

import { getAuthFromReq, isAllowed, clearSessionCookie } from './_lib.js'

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store')

  const claims = getAuthFromReq(req)
  if (!claims) {
    return res.status(401).json({ authenticated: false })
  }

  // Re-check allowlist on every request — lets you revoke access by removing
  // an email from ALLOWED_EMAILS without waiting for the cookie to expire.
  if (!isAllowed(claims.email)) {
    clearSessionCookie(res)
    return res.status(401).json({ authenticated: false, error: 'not-authorised' })
  }

  return res.status(200).json({
    authenticated: true,
    email: claims.email,
    expiresAt: claims.expiry,
  })
}
