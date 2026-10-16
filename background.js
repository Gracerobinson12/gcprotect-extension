// GC Protect — Background Service Worker V3.1.0
// Fixes: MV3 service worker keepalive, async-safe message handling,
// retry queue, resilient sync.

const SYNC_API = 'https://www.gcprotect.tech/api/log-event'
const REFRESH_API = 'https://www.gcprotect.tech/api/refresh-token'

// ============================================================
// SERVICE WORKER KEEPALIVE
// MV3 service workers die after 30s of inactivity. The chrome.alarms
// API keeps them alive on a schedule. We also install the alarm on
// startup/install so it's always present.
// ============================================================
chrome.runtime.onInstalled.addListener(() => {
  ensureAlarms()
  syncPendingLogs().catch(() => {})
})
chrome.runtime.onStartup.addListener(() => {
  ensureAlarms()
  syncPendingLogs().catch(() => {})
})

function ensureAlarms() {
  chrome.alarms.get('audit_sync', (a) => {
    if (!a) chrome.alarms.create('audit_sync', { periodInMinutes: 0.5 })
  })
  chrome.alarms.get('keepalive', (a) => {
    if (!a) chrome.alarms.create('keepalive', { periodInMinutes: 0.4 })
  })
}

// Run alarm setup on every service worker boot too
ensureAlarms()

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'audit_sync' || alarm.name === 'keepalive') {
    syncPendingLogs().catch((e) => console.log('[GC Sync] alarm sync error:', e.message))
  }
})

// ============================================================
// MESSAGE ROUTER
// Pattern: ALWAYS return true for async handlers, ALWAYS call
// sendResponse exactly once, wrap handler in try/catch so a thrown
// error can't eat the response.
// ============================================================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || !msg.type) {
    sendResponse({ ok: false, error: 'bad_message' })
    return false
  }

  switch (msg.type) {
    case 'LOG':
      handleLogEvent(msg.data)
        .then(() => sendResponse({ ok: true }))
        .catch((e) => sendResponse({ ok: false, error: e.message }))
      return true

    case 'OPEN_TRANSPARENCY':
      chrome.windows.create({
        url: chrome.runtime.getURL('transparency.html'),
        type: 'popup',
        width: 400,
        height: 640,
      }, () => sendResponse({ ok: true }))
      return true

    case 'SIGN_IN_SUCCESS':
      handleSignIn(msg)
        .then(() => sendResponse({ ok: true }))
        .catch((e) => sendResponse({ ok: false, error: e.message }))
      return true

    case 'SIGN_OUT':
      chrome.storage.local.remove(
        ['gc_auth_token', 'gc_refresh_token', 'gc_user_email', 'gc_signed_in_at',
         'gc_token_issued_at', 'gc_pending_logs', 'gc_last_sync'],
        () => sendResponse({ ok: true })
      )
      return true

    case 'GET_AUTH_STATE':
      chrome.storage.local.get(['gc_auth_token', 'gc_user_email'], (d) => {
        sendResponse({
          signedIn: !!d.gc_auth_token,
          email: d.gc_user_email || null,
        })
      })
      return true

    case 'FORCE_SYNC':
      (async () => {
        try {
          await backfillLocalEvents()
          await syncPendingLogs()
          sendResponse({ ok: true })
        } catch (e) {
          sendResponse({ ok: false, error: e.message })
        }
      })()
      return true

    case 'BACKFILL_LOCAL':
      backfillLocalEvents()
        .then((count) => {
          syncPendingLogs().catch(() => {})
          sendResponse({ ok: true, backfilled: count })
        })
        .catch((e) => sendResponse({ ok: false, error: e.message }))
      return true

    default:
      sendResponse({ ok: false, error: 'unknown_type' })
      return false
  }
})

async function handleSignIn(msg) {
  await chrome.storage.local.set({
    gc_auth_token: msg.token,
    gc_refresh_token: msg.refreshToken || null,
    gc_user_email: msg.email || '',
    gc_signed_in_at: new Date().toISOString(),
    gc_token_issued_at: Date.now(),
  })
  console.log('[GC Auth] Signed in as', msg.email || '(unknown)')
  await backfillLocalEvents()
  await syncPendingLogs()
}

async function backfillLocalEvents() {
  const stored = await chrome.storage.local.get(['log', 'gc_pending_logs', 'gc_backfill_done'])
  const log = stored.log || []
  const pending = stored.gc_pending_logs || []

  if (log.length === 0 || stored.gc_backfill_done) return 0

  const toBackfill = log.map((entry) => ({
    platform: entry.platform || 'Unknown',
    risk_score: Math.max(0, Math.min(100, Number(entry.score) || 0)),
    fields_detected: Math.max(0, Number(entry.count) || 0),
    field_types: Array.isArray(entry.types) ? entry.types.slice(0, 20) : [],
    mode: entry.mode === 'personalized' ? 'personalized' : 'strict',
    action: ['protected', 'unprotected', 'canceled', 'blocked'].includes(entry.action)
      ? entry.action
      : 'protected',
    timestamp: entry.timestamp || new Date().toISOString(),
  }))

  const newPending = [...pending, ...toBackfill]
  await chrome.storage.local.set({
    gc_pending_logs: newPending,
    gc_backfill_done: true,
  })
  console.log(`[GC Sync] Backfilled ${toBackfill.length} local events to sync queue`)
  return toBackfill.length
}

async function handleLogEvent(eventData) {
  if (!eventData) return
  const stored = await chrome.storage.local.get(['log', 'gc_auth_token', 'gc_pending_logs'])
  const log = stored.log || []
  const timestamp = new Date().toISOString()
  const newEntry = {
    ...eventData,
    timestamp,
    id: crypto.randomUUID(),
  }
  log.unshift(newEntry)
  if (log.length > 200) log.length = 200

  const pending = stored.gc_pending_logs || []
  if (stored.gc_auth_token) {
    pending.push({
      platform: eventData.platform || 'Unknown',
      risk_score: Math.max(0, Math.min(100, Number(eventData.score) || 0)),
      fields_detected: Math.max(0, Number(eventData.count) || 0),
      field_types: Array.isArray(eventData.types) ? eventData.types.slice(0, 20) : [],
      mode: eventData.mode === 'personalized' ? 'personalized' : 'strict',
      action: ['protected', 'unprotected', 'canceled', 'blocked'].includes(eventData.action)
        ? eventData.action
        : 'protected',
      timestamp,
    })
  }
  await chrome.storage.local.set({ log, gc_pending_logs: pending })

  // Opportunistic sync — don't block the response
  if (stored.gc_auth_token && pending.length >= 1) {
    syncPendingLogs().catch(() => {})
  }
}

async function refreshAccessToken() {
  try {
    const { gc_refresh_token } = await chrome.storage.local.get('gc_refresh_token')
    if (!gc_refresh_token) {
      console.log('[GC Auth] No refresh token available')
      return false
    }

    const response = await fetch(REFRESH_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: gc_refresh_token }),
    })

    if (!response.ok) {
      console.log('[GC Auth] Refresh failed:', response.status)
      return false
    }

    const data = await response.json()
    if (data.access_token) {
      await chrome.storage.local.set({
        gc_auth_token: data.access_token,
        gc_refresh_token: data.refresh_token || gc_refresh_token,
        gc_token_issued_at: Date.now(),
      })
      console.log('[GC Auth] ✓ Token refreshed successfully')
      return true
    }
    return false
  } catch (e) {
    console.log('[GC Auth] Refresh error:', e.message)
    return false
  }
}

// Mutex so overlapping alarm fires don't both sync and double-remove entries
let syncing = false

async function syncPendingLogs() {
  if (syncing) return
  syncing = true
  try {
    const { gc_auth_token, gc_pending_logs } = await chrome.storage.local.get([
      'gc_auth_token',
      'gc_pending_logs',
    ])

    if (!gc_auth_token) return
    if (!gc_pending_logs || gc_pending_logs.length === 0) {
      await chrome.storage.local.set({ gc_last_sync: new Date().toISOString() })
      return
    }

    const batch = gc_pending_logs.slice(0, 100)
    console.log(`[GC Sync] Syncing ${batch.length} events...`)

    let response
    try {
      response = await fetch(SYNC_API, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${gc_auth_token}`,
        },
        body: JSON.stringify({ events: batch }),
      })
    } catch (netErr) {
      console.log('[GC Sync] Network error, will retry next alarm:', netErr.message)
      return
    }

    if (response.status === 401) {
      console.log('[GC Sync] Token expired, attempting refresh...')
      const refreshed = await refreshAccessToken()
      if (!refreshed) {
        console.log('[GC Sync] Refresh failed, user needs to re-sign in')
        await chrome.storage.local.remove(['gc_auth_token', 'gc_refresh_token', 'gc_user_email'])
        return
      }
      const { gc_auth_token: newToken } = await chrome.storage.local.get('gc_auth_token')
      try {
        response = await fetch(SYNC_API, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${newToken}`,
          },
          body: JSON.stringify({ events: batch }),
        })
      } catch (netErr) {
        console.log('[GC Sync] Retry network error:', netErr.message)
        return
      }
    }

    if (response.ok) {
      // Re-read queue to avoid race with concurrent handleLogEvent writes
      const { gc_pending_logs: currentQueue } = await chrome.storage.local.get('gc_pending_logs')
      const remaining = (currentQueue || []).slice(batch.length)
      await chrome.storage.local.set({
        gc_pending_logs: remaining,
        gc_last_sync: new Date().toISOString(),
      })
      console.log(`[GC Sync] ✓ Synced ${batch.length} events, ${remaining.length} remaining`)
      if (remaining.length > 0) {
        setTimeout(() => syncPendingLogs().catch(() => {}), 2000)
      }
    } else {
      const errorText = await response.text().catch(() => '')
      console.log(`[GC Sync] API returned ${response.status}: ${errorText}`)
    }
  } catch (error) {
    console.log('[GC Sync] Error:', error.message)
  } finally {
    syncing = false
  }
}
