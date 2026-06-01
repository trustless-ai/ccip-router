// In-memory log ring buffer — last 200 lines, accessible via /admin/api/logs.
// Imported once at startup; side-effect patches console globally.

export type LogEntry = {
  ts:    number               // unix ms
  level: 'info' | 'warn' | 'error'
  msg:   string
}

const MAX  = 200
const ring: LogEntry[] = []

function push(level: LogEntry['level'], args: unknown[]) {
  ring.push({ ts: Date.now(), level, msg: args.map(String).join(' ') })
  if (ring.length > MAX) ring.shift()
}

const _log   = console.log.bind(console)
const _warn  = console.warn.bind(console)
const _error = console.error.bind(console)

console.log   = (...a) => { _log(...a);   push('info',  a) }
console.warn  = (...a) => { _warn(...a);  push('warn',  a) }
console.error = (...a) => { _error(...a); push('error', a) }

export function getLogs(): LogEntry[] {
  return [...ring]
}
