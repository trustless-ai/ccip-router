import { Hono } from 'hono'

export const staticRouter = new Hono()

// Router icon — a central node with 4 connections radiating out
const FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32" fill="none">
  <!-- outer connection dots -->
  <circle cx="4"  cy="16" r="2.5" fill="#818cf8" opacity="0.7"/>
  <circle cx="28" cy="16" r="2.5" fill="#818cf8" opacity="0.7"/>
  <circle cx="16" cy="4"  r="2.5" fill="#818cf8" opacity="0.7"/>
  <circle cx="16" cy="28" r="2.5" fill="#818cf8" opacity="0.7"/>
  <!-- connection lines -->
  <line x1="6.5"  y1="16" x2="10" y2="16" stroke="#6366f1" stroke-width="1.5" stroke-linecap="round"/>
  <line x1="22"   y1="16" x2="25.5" y2="16" stroke="#6366f1" stroke-width="1.5" stroke-linecap="round"/>
  <line x1="16"   y1="6.5" x2="16" y2="10" stroke="#6366f1" stroke-width="1.5" stroke-linecap="round"/>
  <line x1="16"   y1="22" x2="16" y2="25.5" stroke="#6366f1" stroke-width="1.5" stroke-linecap="round"/>
  <!-- central router body -->
  <rect x="10" y="10" width="12" height="12" rx="3" fill="#6366f1"/>
  <!-- ports -->
  <circle cx="13" cy="16" r="1.2" fill="white" opacity="0.9"/>
  <circle cx="16" cy="16" r="1.2" fill="white" opacity="0.9"/>
  <circle cx="19" cy="16" r="1.2" fill="white" opacity="0.9"/>
  <!-- status light -->
  <circle cx="13" cy="13" r="0.9" fill="#4ade80"/>
</svg>`

staticRouter.get('/favicon.svg', (c) => {
  c.header('Content-Type', 'image/svg+xml')
  c.header('Cache-Control', 'public, max-age=86400')
  return c.body(FAVICON_SVG)
})
