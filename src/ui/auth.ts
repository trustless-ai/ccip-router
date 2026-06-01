import { createHash } from 'node:crypto'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import type { MiddlewareHandler } from 'hono'

// Derive a fixed session token from the secret — rotating the secret invalidates all sessions
export function makeSessionToken(secret: string): string {
  return createHash('sha256').update('ccip-router:' + secret).digest('hex')
}

// Applies to all /admin/* routes.
// If adminSecret is null → open access (dev mode, warning shown in UI).
// Otherwise: check cookie (browser) or Authorization: Bearer <secret> (API).
export function requireAdmin(adminSecret: string | null): MiddlewareHandler {
  return async (c, next) => {
    if (!adminSecret) return next()

    // Login/logout are always public — they ARE the auth mechanism
    const path = c.req.path
    if (path.endsWith('/login') || path.endsWith('/logout')) return next()

    const token = makeSessionToken(adminSecret)

    // Cookie path — browser sessions
    const cookie = getCookie(c, 'admin_session')
    if (cookie === token) return next()

    // Bearer token — programmatic API access
    const auth = c.req.header('Authorization')
    if (auth === `Bearer ${adminSecret}`) return next()

    // API routes → 401 JSON
    if (c.req.path.startsWith('/admin/api')) {
      return c.json({ error: 'unauthorized' }, 401)
    }

    // Dashboard routes → login page
    return c.redirect('/admin/login')
  }
}

export function setAdminSession(c: Parameters<MiddlewareHandler>[0], secret: string) {
  setCookie(c, 'admin_session', makeSessionToken(secret), {
    httpOnly: true,
    sameSite: 'Strict',
    path:     '/admin',
    maxAge:   60 * 60 * 24 * 7, // 7 days
  })
}

export function clearAdminSession(c: Parameters<MiddlewareHandler>[0]) {
  deleteCookie(c, 'admin_session', { path: '/admin' })
}
