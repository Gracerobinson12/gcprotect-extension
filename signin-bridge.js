// GC Protect — Sign-in bridge V3.1.0
// Runs on gcprotect.tech/extension-signin — relays auth tokens from
// the signed-in web page into the extension's background service worker.
//
// FIX: accept BOTH www.gcprotect.tech and gcprotect.tech origins.
// FIX: emit a status log so you can tell in DevTools whether the bridge
// fired. FIX: retry the chrome.runtime.sendMessage if the first attempt
// fails because the service worker is cold.

(function() {
  'use strict'

  var ALLOWED_ORIGINS = [
    'https://www.gcprotect.tech',
    'https://gcprotect.tech',
  ]

  function sendToBg(payload, attempt) {
    attempt = attempt || 1
    try {
      chrome.runtime.sendMessage(payload, function(response) {
        if (chrome.runtime.lastError) {
          console.log('[GC Signin Bridge] runtime error:', chrome.runtime.lastError.message)
          if (attempt < 3) {
            setTimeout(function() { sendToBg(payload, attempt + 1) }, 500 * attempt)
          }
          return
        }
        if (response && response.ok) {
          console.log('[GC Signin Bridge] ✓ Auth relayed to extension')
          // Notify the page so it can show a success UI
          try {
            window.postMessage({ type: 'GC_PROTECT_AUTH_RECEIVED' }, '*')
          } catch(e) {}
          // Clean up any leftover token in localStorage
          try {
            localStorage.removeItem('gc_protect_auth_token')
            localStorage.removeItem('gc_protect_refresh_token')
            localStorage.removeItem('gc_protect_user_email')
          } catch(e) {}
        } else {
          console.log('[GC Signin Bridge] background returned:', response)
        }
      })
    } catch (e) {
      console.log('[GC Signin Bridge] sendMessage threw:', e.message)
      if (attempt < 3) {
        setTimeout(function() { sendToBg(payload, attempt + 1) }, 500 * attempt)
      }
    }
  }

  // Listen for postMessage from the signin page's own JS
  window.addEventListener('message', function(event) {
    if (ALLOWED_ORIGINS.indexOf(event.origin) < 0) return
    if (!event.data || event.data.type !== 'GC_PROTECT_AUTH') return
    if (!event.data.token) {
      console.log('[GC Signin Bridge] GC_PROTECT_AUTH received but no token')
      return
    }
    console.log('[GC Signin Bridge] ✓ Got token from page, relaying…')
    sendToBg({
      type: 'SIGN_IN_SUCCESS',
      token: event.data.token,
      refreshToken: event.data.refreshToken || null,
      email: event.data.email || '',
    })
  })

  // Fallback: on page load, check localStorage for a staged token
  function tryLocalStorageFallback() {
    try {
      var token = localStorage.getItem('gc_protect_auth_token')
      if (!token) return
      var refreshToken = localStorage.getItem('gc_protect_refresh_token')
      var email = localStorage.getItem('gc_protect_user_email')
      console.log('[GC Signin Bridge] ✓ Found token in localStorage, relaying…')
      sendToBg({
        type: 'SIGN_IN_SUCCESS',
        token: token,
        refreshToken: refreshToken || null,
        email: email || '',
      })
    } catch (e) {
      console.log('[GC Signin Bridge] localStorage read error:', e.message)
    }
  }

  tryLocalStorageFallback()
  // Also check 1s later in case the page writes it after our script runs
  setTimeout(tryLocalStorageFallback, 1000)
  setTimeout(tryLocalStorageFallback, 3000)

  console.log('[GC Signin Bridge] V3.1.0 active on', location.origin)
})()
