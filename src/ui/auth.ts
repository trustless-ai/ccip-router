import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import type { MiddlewareHandler } from 'hono'
import { createSession, getSession, deleteSession } from './siwe.js'

// Return the wallet address associated with the current session cookie, or null.
export function getSessionAddress(c: Parameters<MiddlewareHandler>[0]): `0x${string}` | null {
  const token = getCookie(c, 'admin_session')
  if (!token) return null
  return getSession(token)
}

// Applies to all /admin/* routes.
// authorizedAddress: set admin wallet — only this address can log in via SIWE
// adminSecret:       optional Bearer-token fallback for CLI / scripts
// claimMode:         true when adminAddress is unset but a gatewayKey exists → require login (claim flow)
// If authorizedAddress, adminSecret, and claimMode are all falsy → open access (dev mode)
export function requireAdmin(
  authorizedAddress: string | null,
  adminSecret:       string | null,
  claimMode:         boolean = false,
): MiddlewareHandler {
  return async (c, next) => {
    if (!authorizedAddress && !adminSecret && !claimMode) return next()

    const path = c.req.path
    // Auth endpoints are always public — they ARE the auth mechanism
    if (
      path.endsWith('/login')       ||
      path.endsWith('/logout')      ||
      path.endsWith('/siwe/nonce')  ||
      path.endsWith('/siwe/verify') ||
      path.endsWith('/siwe/reset')
    ) return next()

    // SIWE session check
    if (authorizedAddress) {
      const sessionAddr = getSessionAddress(c)
      if (sessionAddr?.toLowerCase() === authorizedAddress.toLowerCase()) return next()
    }

    // Bearer token fallback (for CLI / scripts)
    const auth = c.req.header('Authorization')
    if (adminSecret && auth === `Bearer ${adminSecret}`) return next()

    if (c.req.path.startsWith('/admin/api')) {
      return c.json({ error: 'unauthorized' }, 401)
    }
    return c.redirect('/admin/login')
  }
}

export function setAdminSession(c: Parameters<MiddlewareHandler>[0], address: `0x${string}`) {
  const token = createSession(address)
  setCookie(c, 'admin_session', token, {
    httpOnly: true,
    sameSite: 'Strict',
    path:     '/admin',
    maxAge:   60 * 60 * 24 * 7,  // 7 days
  })
}

export function clearAdminSession(c: Parameters<MiddlewareHandler>[0]) {
  const token = getCookie(c, 'admin_session')
  if (token) deleteSession(token)
  deleteCookie(c, 'admin_session', { path: '/admin' })
}
