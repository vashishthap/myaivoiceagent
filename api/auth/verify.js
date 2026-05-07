// GET /api/auth/verify?token=<magic-link-token>
//
// Validates the magic-link token, issues a 7-day session cookie, redirects to /app.
// Errors redirect back to /app/login?error=...
//
// We swap the short magic-link token for a longer-lived session token here.
// Both share the same HMAC scheme; only the TTL differs.

import { verifyToken, createToken, isAllowed, setSessionCookie, SESSION_TTL, getSiteUrl } from './_lib.js'

export default async function handler(req, res) {
  const SITE = getSiteUrl(req)
  const token = req.query?.token
  if (!token) {
    return redirectLogin(res, SITE, 'missing-token')
  }

  const claims = verifyToken(typeof token === 'string' ? token : token[0])
  if (!claims) {
    return redirectLogin(res, SITE, 'invalid-or-expired')
  }
  if (!isAllowed(claims.email)) {
    return redirectLogin(res, SITE, 'not-authorised')
  }

  // Mint a fresh session token (7 days) and set the cookie.
  const session = createToken(claims.email, SESSION_TTL)
  setSessionCookie(res, session)

  res.statusCode = 302
  res.setHeader('Location', `${SITE}/app`)
  res.end()
}

function redirectLogin(res, site, reason) {
  res.statusCode = 302
  res.setHeader('Location', `${site}/app/login?error=${encodeURIComponent(reason)}`)
  res.end()
}
