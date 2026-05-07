// POST /api/auth/logout
// Clears the session cookie. Idempotent — always returns 200.

import { clearSessionCookie } from './_lib.js'

export default async function handler(req, res) {
  clearSessionCookie(res)
  return res.status(200).json({ ok: true })
}
