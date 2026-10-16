// GC Protect — Popup Logic V3.1.0
// Fixes: button wiring timing, service-worker-dead handling,
// force-sync-on-open, real-time refresh.

// Safe message helper — handles dead service worker
function sendMessage(payload, cb) {
  try {
    chrome.runtime.sendMessage(payload, function(response) {
      if (chrome.runtime.lastError) {
        console.log('[GC Popup] runtime error:', chrome.runtime.lastError.message)
        if (cb) cb(null)
        return
      }
      if (cb) cb(response)
    })
  } catch (e) {
    console.log('[GC Popup] sendMessage threw:', e.message)
    if (cb) cb(null)
  }
}

function $(id) { return document.getElementById(id) }

function render() {
  // Auth state first — wake the service worker up
  sendMessage({ type: 'GET_AUTH_STATE' }, function(response) {
    var signedIn = response && response.signedIn
    var email = response && response.email

    if (signedIn) {
      $('authSignedOut').style.display = 'none'
      $('authSignedIn').style.display = 'flex'
      $('userEmail').textContent = email || ''
    } else {
      $('authSignedOut').style.display = 'flex'
      $('authSignedIn').style.display = 'none'
    }
  })

  // Load log + stats
  chrome.storage.local.get(['enabled', 'log', 'gc_pending_logs', 'gc_last_sync'], function(d) {
    var enabled = d.enabled !== false
    var log = d.log || []

    $('tg').checked = enabled
    $('status').textContent = enabled ? 'READY' : 'OFF'
    $('status').className = 'status' + (enabled ? '' : ' off')

    var prot = log.filter(function(e){return e.action==='protected'})
    var unsafe = log.filter(function(e){return e.action==='unprotected'}).length
    var fields = prot.reduce(function(s,e){return s+(e.count||0)},0)
    var critical = prot.filter(function(e){return e.score>=70}).length

    $('s1').textContent = prot.length
    $('s2').textContent = fields
    $('s3').textContent = critical
    $('s4').textContent = unsafe

    // Sync status
    var pending = d.gc_pending_logs || []
    var syncBadge = $('syncBadge')
    if (pending.length > 0) {
      syncBadge.textContent = '⟳ ' + pending.length + ' pending'
      syncBadge.className = 'syncBadge pending'
      syncBadge.style.display = 'inline'
    } else if (d.gc_last_sync) {
      var ago = Math.floor((Date.now() - new Date(d.gc_last_sync).getTime()) / 1000)
      var agoText = ago < 60 ? ago + 's ago' : Math.floor(ago/60) + 'm ago'
      syncBadge.textContent = '✓ synced ' + agoText
      syncBadge.className = 'syncBadge'
      syncBadge.style.display = 'inline'
    } else {
      syncBadge.style.display = 'none'
    }

    // Render log items
    var logsEl = $('logs')
    if (log.length === 0) {
      logsEl.innerHTML = '<div class="empty">No activity yet.<br>GC Protect activates automatically<br>on any AI platform.</div>'
      return
    }

    var html = ''
    for (var i = 0; i < Math.min(20, log.length); i++) {
      var e = log[i]
      var color = e.score >= 70 ? '#FF453A' : e.score >= 40 ? '#FF9F0A' : '#30D158'
      var icon = e.action === 'protected' ? '🛡' : '⚠️'
      var time = new Date(e.timestamp).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'})
      html += '<div class="item"><div class="dot" style="background:' + color + '"></div>' +
              '<span style="flex:1;color:#ccc">' + icon + ' ' + escapeText(e.platform) + '</span>' +
              '<span style="color:#666;font-size:11px">' + (e.score || 0) + '/100</span>' +
              '<span style="color:#444;font-size:10px">' + time + '</span></div>'
    }
    logsEl.innerHTML = html
  })

  // Force a sync in the background — refreshes badge after
  sendMessage({ type: 'FORCE_SYNC' }, function() {
    // Re-read storage to update badge
    chrome.storage.local.get(['gc_pending_logs', 'gc_last_sync'], function(d) {
      var pending = d.gc_pending_logs || []
      var syncBadge = $('syncBadge')
      if (pending.length > 0) {
        syncBadge.textContent = '⟳ ' + pending.length + ' pending'
        syncBadge.className = 'syncBadge pending'
      } else if (d.gc_last_sync) {
        syncBadge.textContent = '✓ synced just now'
        syncBadge.className = 'syncBadge'
      }
    })
  })
}

function escapeText(s) {
  var div = document.createElement('div')
  div.textContent = String(s == null ? '' : s)
  return div.innerHTML
}

function wireButtons() {
  // Protection toggle
  $('tg').addEventListener('change', function(e) {
    chrome.storage.local.set({ enabled: e.target.checked }, function() {
      $('status').textContent = e.target.checked ? 'READY' : 'OFF'
      $('status').className = 'status' + (e.target.checked ? '' : ' off')
    })
  })

  // Sign in — opens website, keeps popup open so user sees new state when they return
  $('signInBtn').addEventListener('click', function() {
    chrome.tabs.create({ url: 'https://www.gcprotect.tech/extension-signin' })
    // Don't close popup — let the SIGN_IN_SUCCESS message refresh when user navigates back
    // But popup WILL auto-close when user clicks the new tab. That's fine.
  })

  // Sign out
  $('signOutBtn').addEventListener('click', function() {
    if (!confirm('Sign out of audit log sync?\n\nYour protection still works. Future events will log locally only.')) return
    sendMessage({ type: 'SIGN_OUT' }, function() {
      render()
    })
  })

  // Your Data button — opens transparency panel
  $('dataBtn').addEventListener('click', function() {
    chrome.windows.create({
      url: chrome.runtime.getURL('transparency.html'),
      type: 'popup',
      width: 400,
      height: 640,
    })
  })

  // Clear local log — keeps synced events in Supabase
  $('clearBtn').addEventListener('click', function() {
    if (!confirm('Clear all local logs?\n\nSynced events remain in your account.')) return
    chrome.storage.local.set({ log: [] }, function() {
      render()
    })
  })

  // Export local log as CSV
  $('exportBtn').addEventListener('click', function() {
    chrome.storage.local.get('log', function(d) {
      var log = d.log || []
      if (log.length === 0) { alert('No activity to export.'); return }
      var csv = 'Date,Time,Platform,Score,Action,Fields\n'
      for (var i = 0; i < log.length; i++) {
        var e = log[i]
        var dt = new Date(e.timestamp)
        csv += dt.toLocaleDateString() + ',' + dt.toLocaleTimeString() + ',' +
               (e.platform || '') + ',' + (e.score || 0) + ',' +
               (e.action || '') + ',' + (e.count || 0) + '\n'
      }
      var blob = new Blob([csv], { type: 'text/csv' })
      var a = document.createElement('a')
      a.href = URL.createObjectURL(blob)
      a.download = 'gc-protect-log-' + new Date().toISOString().split('T')[0] + '.csv'
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
    })
  })
}

// Wait for DOM so every element is ready before we touch it
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', function() {
    wireButtons()
    render()
  })
} else {
  wireButtons()
  render()
}
