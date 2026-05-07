// Shared auth helpers for the /app admin dashboard.
//
// HMAC-signed stateless tokens (no DB needed). Token shape:
//     base64url("<email>|<expiry>|<sig>")
// where sig = HMAC_SHA256("<email>|<expiry>", JWT_SECRET).
//
// Two contexts:
//   - Magic-link tokens   — short TTL (10 min), used once via /api/auth/verify
//   - Session cookie tokens — longer TTL (7 days), set by /api/auth/verify, read by /api/auth/me
//
// Files prefixed with _ aren't routed by Vercel, so this stays internal.

import crypto from 'node:crypto'

export const COOKIE_NAME = 'seo_admin_token'
export const SESSION_TTL = 60 * 60 * 24 * 7 // 7 days
export const MAGIC_LINK_TTL = 60 * 10       // 10 minutes

function hmac(payload) {
  const secret = process.env.JWT_SECRET
  if (!secret || secret.length < 16) {
    throw new Error('JWT_SECRET env var missing or too short (min 16 chars)')
  }
  return crypto.createHmac('sha256', secret).update(payload).digest('hex')
}

export function createToken(email, ttlSec) {
  const expiry = Math.floor(Date.now() / 1000) + ttlSec
  const payload = `${email.toLowerCase()}|${expiry}`
  const sig = hmac(payload)
  return Buffer.from(`${payload}|${sig}`).toString('base64url')
}

export function verifyToken(token) {
  if (!token) return null
  try {
    const decoded = Buffer.from(token, 'base64url').toString('utf8')
    const parts = decoded.split('|')
    if (parts.length !== 3) return null
    const [email, expiryStr, sig] = parts
    const expiry = parseInt(expiryStr, 10)
    if (!Number.isFinite(expiry) || Math.floor(Date.now() / 1000) > expiry) return null
    const expected = hmac(`${email}|${expiry}`)
    // timing-safe equality
    const a = Buffer.from(sig, 'hex')
    const b = Buffer.from(expected, 'hex')
    if (a.length !== b.length) return null
    if (!crypto.timingSafeEqual(a, b)) return null
    return { email, expiry }
  } catch {
    return null
  }
}

export function isAllowed(email) {
  const allowed = (process.env.ALLOWED_EMAILS || '')
    .split(',')
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean)
  if (allowed.length === 0) return false
  return allowed.includes((email || '').toLowerCase())
}

export function parseCookies(req) {
  const header = req.headers.cookie || ''
  const out = {}
  header.split(';').forEach((c) => {
    const idx = c.indexOf('=')
    if (idx === -1) return
    const k = c.slice(0, idx).trim()
    const v = c.slice(idx + 1).trim()
    if (k) out[k] = decodeURIComponent(v)
  })
  return out
}

export function getAuthFromReq(req) {
  const cookies = parseCookies(req)
  return verifyToken(cookies[COOKIE_NAME])
}

export function setSessionCookie(res, token) {
  res.setHeader(
    'Set-Cookie',
    [
      `${COOKIE_NAME}=${encodeURIComponent(token)}`,
      'Path=/',
      `Max-Age=${SESSION_TTL}`,
      'HttpOnly',
      'Secure',
      'SameSite=Lax',
    ].join('; '),
  )
}

export function clearSessionCookie(res) {
  res.setHeader(
    'Set-Cookie',
    [`${COOKIE_NAME}=`, 'Path=/', 'Max-Age=0', 'HttpOnly', 'Secure', 'SameSite=Lax'].join('; '),
  )
}

export function isValidEmail(email) {
  if (typeof email !== 'string') return false
  // Permissive RFC-5322-lite — good enough for SMTP delivery.
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length < 254
}

// Returns the canonical site URL for the current request, e.g.
// "https://www.myaivoiceagent.co" on production
// "https://myaivoiceagent-git-feat-ad-...-vercel.app" on Preview.
// Lets magic-link emails sent from a Preview deploy point back to that Preview.
export function getSiteUrl(req) {
  const host = req.headers && req.headers.host
  const proto = (req.headers && req.headers['x-forwarded-proto']) || 'https'
  if (!host) return 'https://www.myaivoiceagent.co'
  return `${proto}://${host}`
}
