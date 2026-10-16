// GC Protect V3.1.0 — HARDENED BUILD
// Fixes: stronger 8-char tokens, no AI refusal hints, precise platform
// detection, SPA-safe vault, performant restoration, ProseMirror/Lexical/Quill-
// safe writes, fewer false positives, better focus capture, improved phone
// & address patterns.

(function() {
  'use strict'

  // ============================================================
  // GUARD: Don't run on our own site
  // ============================================================
  var OWN_HOSTS = ['gcprotect.tech', 'localhost', '127.0.0.1', 'vercel.app']
  for (var i = 0; i < OWN_HOSTS.length; i++) {
    if (location.hostname === OWN_HOSTS[i] || location.hostname.endsWith('.' + OWN_HOSTS[i])) {
      return
    }
  }

  // ============================================================
  // STATE
  // ============================================================
  var enabled = true
  var overlayOpen = false
  var ignoredText = ''
  var vault = new Map()    // token -> real value
  var mode = 'strict'      // 'strict' | 'personalized'
  var CURRENT_PLATFORM = null

  try {
    chrome.storage.local.get(['enabled', 'mode'], function(d) {
      if (d.enabled === false) enabled = false
      if (d.mode === 'personalized') mode = 'personalized'
    })
  } catch(e) {}

  // Transparency panel bridge
  try {
    chrome.runtime.onMessage.addListener(function(msg, sender, sendResponse) {
      if (msg.type === 'GET_VAULT_STATE') {
        var entries = []
        for (var pair of vault) entries.push([pair[0], pair[1]])
        sendResponse({ vault: entries, count: entries.length })
        return true
      }
      if (msg.type === 'CLEAR_VAULT') {
        vault.clear()
        sendResponse({ ok: true })
        return true
      }
    })
  } catch(e) {}

  // Only clear vault on actual tab close (pagehide, not persisted),
  // NOT on SPA navigation.
  window.addEventListener('pagehide', function(e) {
    if (!e.persisted) vault.clear()
  })

  // ============================================================
  // Precise platform detection (hostname whitelist, not substring)
  // ============================================================
  function platform() {
    if (CURRENT_PLATFORM) return CURRENT_PLATFORM
    var h = location.hostname.toLowerCase()
    var p
    if (h === 'chatgpt.com' || h === 'chat.openai.com' || h.endsWith('.chatgpt.com') || h.endsWith('.openai.com')) p = 'ChatGPT'
    else if (h === 'claude.ai' || h.endsWith('.claude.ai')) p = 'Claude'
    else if (h === 'gemini.google.com' || h.endsWith('.gemini.google.com')) p = 'Gemini'
    else if (h === 'perplexity.ai' || h === 'www.perplexity.ai' || h.endsWith('.perplexity.ai')) p = 'Perplexity'
    else if (h === 'grok.com' || h === 'x.com' || h === 'twitter.com' || h.endsWith('.grok.com') || h.endsWith('.x.com')) p = 'Grok'
    else p = 'AI'
    CURRENT_PLATFORM = p
    return p
  }

  // ============================================================
  // PATTERNS
  // ============================================================
  var PATTERNS = [
    // SECRETS (sev 3 = critical, 30 pts each)
    { type: 'GITHUB',  re: /\b(ghp|gho|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b/g,     sev: 3 },
    { type: 'AWS',     re: /\b(AKIA|ASIA|AROA)[A-Z0-9]{16}\b/g,                        sev: 3 },
    { type: 'API',     re: /\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b/g,                    sev: 3 },
    { type: 'API',     re: /(?:api[_-]?key|secret[_-]?key|bearer[_\s-]?token)\s*[:=]\s*['"]?[A-Za-z0-9_\-.]{16,}['"]?/gi, sev: 3 },
    { type: 'DB',      re: /\b(postgres|postgresql|mongodb|mongodb\+srv|mysql|redis|rediss):\/\/[^\s"'<>]{6,}/gi, sev: 3 },
    { type: 'PASS',    re: /(?:password|passwd|pwd)\s*[:=]\s*\S{4,}/gi,                sev: 3 },

    // GOV/FINANCIAL IDs (sev 3)
    { type: 'SSN',     re: /\b\d{3}-\d{2}-\d{4}\b/g,                                   sev: 3 },
    { type: 'CC',      re: /\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b/g, sev: 3 },
    { type: 'BANK',    re: /(?:account|acct|routing|aba)\s*(?:no|number|num|#)?\s*:?\s*#?\s*\d{8,17}\b/gi, sev: 3 },
    { type: 'INSID',   re: /\b[A-Z]{2,4}-\d{4,9}(?:-\d{1,4})?\b/g,                     sev: 3 },

    // PII (sev 2 = 15 pts each)
    { type: 'EMAIL',   re: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}\b/g,    sev: 2 },
    // Phone — captures full form including parentheses, dashes, dots
    { type: 'PHONE',   re: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b/g, sev: 2 },
    // Address — up to 4 word street name + optional unit + city/state/zip tail
    { type: 'ADDR',    re: /\b\d{1,5}\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3}\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Drive|Dr|Lane|Ln|Court|Ct|Place|Pl|Way|Circle|Cir|Highway|Hwy|Parkway|Pkwy|Terrace|Ter|Trail|Trl)\b\.?(?:,?\s+(?:Apt|Suite|Unit|#)\s*\d+[A-Z]?)?(?:,\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?,?\s*[A-Z]{2}\s*\d{5}(?:-\d{4})?)?/g, sev: 2 },
    { type: 'DOB',     re: /\b(?:DOB|D\.O\.B\.?|born(?:\s*on)?|birth(?:date|day)?)\s*[:=\-]?\s*(?:0?[1-9]|1[0-2])[\/.\-](?:0?[1-9]|[12]\d|3[01])[\/.\-](?:19|20)\d{2}\b/gi, sev: 2 },

    // SOFT (sev 1 = 8 pts each)
    { type: 'MONEY',   re: /\$\s*(?:\d{1,3}(?:,\d{3})+(?:\.\d{2})?|\d{3,}(?:\.\d{2})?|\d{1,2}\.\d{2}|\d{3,})/g, sev: 1 },
    { type: 'INVOICE', re: /\b(?:INV|invoice)[-#]?\s*\d{4,}\b/gi,                      sev: 1 },
  ]

  var TYPE_LABEL = { GITHUB:'GitHub Token', AWS:'AWS Key', API:'API Key', DB:'Database URL', PASS:'Password', SSN:'SSN', CC:'Credit Card', EMAIL:'Email', PHONE:'Phone', MONEY:'Dollar Amount', BANK:'Bank Account', INVOICE:'Invoice #', NAME:'Person Name', ADDR:'Street Address', DOB:'Date of Birth', INSID:'ID Number' }
  var PREFIX = { GITHUB:'GH', AWS:'AWS', API:'AP', DB:'DB', PASS:'PW', SSN:'SS', CC:'CC', EMAIL:'EM', PHONE:'PH', MONEY:'MN', BANK:'BK', INVOICE:'IN', NAME:'NM', ADDR:'AD', DOB:'DB', INSID:'IX' }

  var NAME_SKIP = new Set(['ChatGPT','Google','Microsoft','Claude','OpenAI','Gemini','Grok','Perplexity','Anthropic','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday','January','February','March','April','May','June','July','August','September','October','November','December','Dear','Hello','Hi','Thank','Please','Best','Kind','Regards','Sincerely','Employee','Client','Customer','Patient','GC','Protect','What','How','Why','When','Where','Who','Type','Last','Write','Draft','Help','Analyze','Make','Give','Show','Tell','Summarize','Explain','Create','List','Provide','Street','Avenue','Boulevard','Road','Drive','Lane','Court','Place','Way','Circle','Highway','Parkway','Terrace','Trail','Suite','Unit','Apt','North','South','East','West','Alabama','Alaska','Arizona','Arkansas','California','Colorado','Connecticut','Delaware','Florida','Georgia','Hawaii','Idaho','Illinois','Indiana','Iowa','Kansas','Kentucky','Louisiana','Maine','Maryland','Massachusetts','Michigan','Minnesota','Mississippi','Missouri','Montana','Nebraska','Nevada','Ohio','Oklahoma','Oregon','Pennsylvania','Tennessee','Texas','Utah','Vermont','Virginia','Washington','Wisconsin','Wyoming','Nashville','Atlanta','Boston','Chicago','Dallas','Denver','Detroit','Houston','Miami','Phoenix','Portland','Seattle','Suggest','Recommend','Follow','Include','Insurance','Diagnosis','Medications','Contact','Address','Phone','Email','Name','Current','Next','Debug','Access','Key','Token','United','States','America','English','Spanish','French','Type','Hypertension','Diabetes'])

  // Strong 8-char base36 token suffix
  function genToken(type, val) {
    for (var pair of vault) {
      if (pair[1] === val) return pair[0]
    }
    var bytes = new Uint8Array(6)
    crypto.getRandomValues(bytes)
    var suffix = ''
    for (var i = 0; i < bytes.length; i++) {
      suffix += bytes[i].toString(36)
    }
    suffix = suffix.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8)
    while (suffix.length < 8) {
      suffix += Math.floor(Math.random() * 36).toString(36).toUpperCase()
    }
    return '⟨' + (PREFIX[type] || 'XX') + suffix + '⟩'
  }

  function scan(text) {
    if (text.indexOf('⟨') >= 0) {
      return { count: 0, protected: text, tokenMap: {}, types: [], score: 0, groups: {}, entities: [] }
    }

    var found = []
    var covered = []
    var seen = new Map()

    function isCovered(s, e) {
      for (var r of covered) if (s < r[1] && e > r[0]) return true
      return false
    }

    for (var p of PATTERNS) {
      var rx = new RegExp(p.re.source, p.re.flags)
      var m
      while ((m = rx.exec(text)) !== null) {
        var val = m[0]
        var start = m.index
        var end = start + val.length
        if (isCovered(start, end)) continue
        var tok = seen.get(val) || genToken(p.type, val)
        seen.set(val, tok)
        found.push({ val: val, tok: tok, type: p.type, start: start, end: end, sev: p.sev })
        covered.push([start, end])
      }
    }

    // Names last so secrets claim their ranges first
    var nameRx = /\b([A-Z][a-z]{1,20})\s+([A-Z][a-z]{1,20})\b/g
    var nm
    while ((nm = nameRx.exec(text)) !== null) {
      if (NAME_SKIP.has(nm[1]) || NAME_SKIP.has(nm[2])) continue
      var val2 = nm[0]
      var start2 = nm.index
      var end2 = start2 + val2.length
      if (isCovered(start2, end2)) continue
      var tok2 = seen.get(val2) || genToken('NAME', val2)
      seen.set(val2, tok2)
      found.push({ val: val2, tok: tok2, type: 'NAME', start: start2, end: end2, sev: 2 })
      covered.push([start2, end2])
    }

    found.sort(function(a, b) { return b.start - a.start })
    var pt = text
    for (var f of found) pt = pt.slice(0, f.start) + f.tok + pt.slice(f.end)

    var tokenMap = {}
    for (var pair of seen) tokenMap[pair[1]] = pair[0]

    var groups = {}
    for (var f2 of found) {
      if (!groups[f2.type]) groups[f2.type] = 0
      groups[f2.type]++
    }

    var score = 0
    for (var f3 of found) score += f3.sev === 3 ? 30 : f3.sev === 2 ? 15 : 8

    var types = []
    for (var t in groups) types.push(t)

    return {
      count: found.length,
      protected: pt,
      tokenMap: tokenMap,
      types: types,
      score: Math.min(score, 100),
      groups: groups,
      entities: found
    }
  }

  // ============================================================
  // BOX DETECTION — Gemini got updated selectors
  // ============================================================
  function findBox() {
    var p = platform()
    var candidates = []

    if (p === 'ChatGPT') {
      candidates = ['#prompt-textarea', 'div[contenteditable="true"][data-lexical-editor]', 'textarea[data-id]']
    } else if (p === 'Claude') {
      candidates = ['div[contenteditable="true"].ProseMirror', 'div[contenteditable="true"][aria-label*="prompt" i]', 'div[contenteditable="true"][aria-label*="message" i]']
    } else if (p === 'Gemini') {
      // Gemini uses rich-textarea with ql-editor (Quill) inside
      candidates = [
        'rich-textarea div.ql-editor[contenteditable="true"]',
        'rich-textarea div[contenteditable="true"]',
        'div.ql-editor[contenteditable="true"]',
        'div[contenteditable="true"][aria-label*="prompt" i]',
        'div[contenteditable="true"][aria-label*="input" i]',
        'div[contenteditable="true"][role="textbox"]',
      ]
    } else if (p === 'Perplexity') {
      candidates = ['textarea[placeholder]', 'div[contenteditable="true"]', 'textarea']
    } else if (p === 'Grok') {
      candidates = ['textarea[placeholder]', 'div[contenteditable="true"]', 'textarea']
    }

    candidates.push('div[contenteditable="true"][aria-multiline="true"]')
    candidates.push('div[contenteditable="true"]')
    candidates.push('textarea[placeholder]')
    candidates.push('textarea')

    for (var sel of candidates) {
      try {
        var els = document.querySelectorAll(sel)
        for (var el of els) {
          if (el.offsetParent !== null && !el.disabled && !el.readOnly) return el
        }
      } catch(e) {}
    }
    return null
  }

  function readBox(box) {
    return box.tagName === 'TEXTAREA' ? box.value : (box.innerText || box.textContent || '')
  }

  // ============================================================
  // writeBox — safe for modern editors (ProseMirror/Lexical/Quill)
  // ============================================================
  function writeBox(box, text) {
    if (box.tagName === 'TEXTAREA') {
      var setter = Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype, 'value').set
      setter.call(box, text)
      box.dispatchEvent(new Event('input', { bubbles: true }))
      box.dispatchEvent(new Event('change', { bubbles: true }))
      return
    }

    box.focus()
    try {
      var sel = window.getSelection()
      sel.removeAllRanges()
      var range = document.createRange()
      range.selectNodeContents(box)
      sel.addRange(range)

      var ok = document.execCommand('insertText', false, text)
      if (ok) {
        box.dispatchEvent(new Event('change', { bubbles: true }))
        return
      }
    } catch(e) {}

    // Fallback — direct DOM write
    try {
      box.innerHTML = ''
      var p = document.createElement('p')
      p.textContent = text
      box.appendChild(p)
      try {
        var ev = new InputEvent('input', { bubbles: true, inputType: 'insertText', data: text })
        box.dispatchEvent(ev)
      } catch(_) {
        box.dispatchEvent(new Event('input', { bubbles: true }))
      }
      box.dispatchEvent(new Event('change', { bubbles: true }))
    } catch(e) {}
  }

  function clickSend() {
    var p = platform()
    var sels
    if (p === 'ChatGPT')       sels = ['button[data-testid="send-button"]', 'button[aria-label*="Send" i]']
    else if (p === 'Claude')   sels = ['button[aria-label*="Send" i]', 'fieldset button:not([disabled])']
    else if (p === 'Gemini')   sels = ['button[aria-label*="Send" i]', 'button.send-button', 'button[mattooltip*="Send" i]', 'button.send-button-container', 'mat-icon[fonticon="send"]']
    else                       sels = ['button[type="submit"]', 'button[aria-label*="Send" i]', 'button[aria-label*="Submit" i]']

    function tryClick() {
      for (var s of sels) {
        try {
          var btns = document.querySelectorAll(s)
          for (var b of btns) {
            // For mat-icon targets, click the parent button
            var target = b.tagName === 'MAT-ICON' ? b.closest('button') : b
            if (!target) continue
            if (!target.disabled && target.offsetParent !== null) { target.click(); return true }
          }
        } catch(e) {}
      }
      for (var b2 of document.querySelectorAll('button, div[role="button"]')) {
        if (b2.disabled || !b2.offsetParent) continue
        var lbl = (b2.getAttribute('aria-label') || '').toLowerCase()
        var tid = (b2.getAttribute('data-testid') || '').toLowerCase()
        if ((lbl.indexOf('send') >= 0 || tid.indexOf('send') >= 0) && lbl.indexOf('cancel') < 0) {
          b2.click(); return true
        }
      }
      return false
    }

    var delays = [80, 250, 600, 1200, 2000]
    var i = 0
    function next() {
      if (i >= delays.length) return
      setTimeout(function() { if (!tryClick()) { i++; next() } }, delays[i++])
    }
    next()
  }

  function toast(msg, color) {
    var old = document.getElementById('gc-toast')
    if (old) old.remove()
    var t = document.createElement('div')
    t.id = 'gc-toast'
    t.textContent = msg
    t.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:2147483647;background:rgba(20,20,22,0.98);border:1px solid ' + color + '60;color:' + color + ';padding:11px 24px;border-radius:22px;font-size:13px;font-weight:600;font-family:-apple-system,sans-serif;pointer-events:none;box-shadow:0 8px 32px rgba(0,0,0,0.5);'
    document.body.appendChild(t)
    setTimeout(function() { t.remove() }, 3000)
  }

  // ============================================================
  // Fast response restoration
  // ============================================================
  var respWatcher = null
  function escapeRegex(s) {
    return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  }

  function buildVaultRegex() {
    if (!vault.size) return null
    var parts = []
    for (var pair of vault) parts.push(escapeRegex(pair[0]))
    parts.sort(function(a, b) { return b.length - a.length })
    return new RegExp(parts.join('|'), 'g')
  }

  function watchResponse() {
    if (respWatcher) respWatcher.disconnect()
    if (!vault.size) return

    var lastRun = 0
    var pending = false
    var vaultRegex = buildVaultRegex()

    function run() {
      pending = false
      if (!vaultRegex) return

      var w = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, {
        acceptNode: function(node) {
          if (node.parentElement) {
            var closest = node.parentElement.closest('#gc-toast, #gc-overlay, #gc-proof')
            if (closest) return NodeFilter.FILTER_REJECT
          }
          return node.nodeValue && node.nodeValue.indexOf('⟨') >= 0
            ? NodeFilter.FILTER_ACCEPT
            : NodeFilter.FILTER_REJECT
        }
      })

      var count = 0
      var node
      while ((node = w.nextNode())) {
        var orig = node.nodeValue
        var replaced = orig.replace(vaultRegex, function(tok) {
          var real = vault.get(tok)
          if (real) { count++; return real }
          return tok
        })
        if (replaced !== orig) node.nodeValue = replaced
      }

      if (count > 0) toast('🔓 ' + count + ' token' + (count !== 1 ? 's' : '') + ' restored in AI response · Only you see the real values', '#30D158')
    }

    respWatcher = new MutationObserver(function() {
      var now = Date.now()
      if (pending) return
      if (now - lastRun < 400) {
        pending = true
        setTimeout(function() { lastRun = Date.now(); run() }, 500)
        return
      }
      lastRun = now
      pending = true
      requestAnimationFrame(run)
    })
    respWatcher.observe(document.body, { childList: true, subtree: true, characterData: true })
  }

  function log(data) {
    try {
      if (chrome && chrome.runtime && chrome.runtime.id) {
        chrome.runtime.sendMessage({ type: 'LOG', data: data }, function() {
          if (chrome.runtime.lastError) {
            console.log('[GC Protect] log send error:', chrome.runtime.lastError.message)
          }
        })
      }
    } catch(e) {}
  }

  function closeOverlay() {
    var el = document.getElementById('gc-overlay')
    if (el) el.remove()
    overlayOpen = false
  }

  function escHtml(s) {
    return String(s).replace(/[&<>"']/g, function(c) {
      return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]
    })
  }

  function showProofPanel(result) {
    var existing = document.getElementById('gc-proof')
    if (existing) existing.remove()

    var SEV_COLOR = { GITHUB:'#FF453A', AWS:'#FF453A', API:'#FF453A', DB:'#FF453A', PASS:'#FF453A', SSN:'#FF453A', CC:'#FF453A', BANK:'#FF453A', INSID:'#FF453A', EMAIL:'#FF9F0A', PHONE:'#FF9F0A', NAME:'#FF9F0A', ADDR:'#FF9F0A', DOB:'#FF9F0A', MONEY:'#FFD60A', INVOICE:'#FFD60A' }

    var rowsHtml = ''
    var shown = new Set()
    for (var e of result.entities) {
      if (shown.has(e.tok)) continue
      shown.add(e.tok)
      var color = SEV_COLOR[e.type] || '#888'
      var masked = e.val.length > 6 ? e.val.substring(0, 3) + '***' : '***'
      rowsHtml += '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;font-size:11px;font-family:monospace;">' +
        '<span style="color:rgba(255,255,255,0.4);flex-shrink:0">' + escHtml(masked) + '</span>' +
        '<span style="color:rgba(255,255,255,0.3);flex-shrink:0">→</span>' +
        '<span style="color:' + color + ';font-weight:600;flex:1">' + escHtml(e.tok) + '</span>' +
        '</div>'
    }

    var panel = document.createElement('div')
    panel.id = 'gc-proof'
    panel.style.cssText = 'position:fixed;bottom:24px;right:24px;width:280px;background:rgba(20,20,22,0.98);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border:1.5px solid #30D158;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,0.7);font-family:-apple-system,sans-serif;overflow:hidden;z-index:2147483646;transform:translateX(320px);transition:transform 0.4s ease-out;'

    panel.innerHTML =
      '<div style="padding:12px 14px;background:linear-gradient(135deg,rgba(48,209,88,0.15),rgba(48,209,88,0.05));border-bottom:1px solid rgba(48,209,88,0.2);display:flex;align-items:center;gap:8px">' +
        '<span style="font-size:18px">✓</span>' +
        '<div style="flex:1;">' +
          '<div style="font-size:13px;font-weight:700;color:#30D158">Protection Applied</div>' +
          '<div style="font-size:10px;color:rgba(255,255,255,0.5);margin-top:1px">' + result.count + ' fields replaced with tokens</div>' +
        '</div>' +
      '</div>' +
      '<div style="padding:10px 14px;max-height:200px;overflow-y:auto">' +
        '<div style="font-size:10px;font-weight:600;color:rgba(255,255,255,0.4);letter-spacing:.05em;margin-bottom:6px">SENT TO ' + escHtml(platform().toUpperCase()) + ' AS:</div>' +
        rowsHtml +
      '</div>' +
      '<div style="padding:8px 14px;background:rgba(48,209,88,0.05);border-top:1px solid rgba(255,255,255,0.05);font-size:10px;color:rgba(255,255,255,0.5);line-height:1.5">' +
        '🔒 Real values stayed in your browser<br>' +
        '🤖 AI only received the tokens above' +
      '</div>' +
      '<div style="padding:8px 14px;display:flex;gap:6px">' +
        '<button id="gcProofClose" style="flex:1;background:rgba(255,255,255,0.06);color:rgba(255,255,255,0.6);border:none;border-radius:6px;padding:6px 10px;font-size:11px;cursor:pointer;font-family:inherit">Got it</button>' +
        '<button id="gcProofExpand" style="flex:1;background:rgba(10,132,255,0.1);color:#0A84FF;border:1px solid rgba(10,132,255,0.2);border-radius:6px;padding:6px 10px;font-size:11px;cursor:pointer;font-family:inherit">See details</button>' +
      '</div>'

    document.body.appendChild(panel)
    setTimeout(function() { panel.style.transform = 'translateX(0)' }, 50)

    document.getElementById('gcProofClose').onclick = function() {
      panel.style.transform = 'translateX(320px)'
      setTimeout(function() { panel.remove() }, 400)
    }
    document.getElementById('gcProofExpand').onclick = function() {
      try {
        if (chrome && chrome.runtime && chrome.runtime.id) {
          chrome.runtime.sendMessage({ type: 'OPEN_TRANSPARENCY' }, function() {
            if (chrome.runtime.lastError) { /* silent */ }
          })
        }
      } catch(e) {}
    }

    setTimeout(function() {
      if (document.getElementById('gc-proof')) {
        panel.style.transform = 'translateX(320px)'
        setTimeout(function() { panel.remove() }, 400)
      }
    }, 8000)
  }

  function showOverlay(result, box) {
    closeOverlay()
    overlayOpen = true

    var riskColor = result.score >= 70 ? '#FF453A' : result.score >= 40 ? '#FF9F0A' : '#FFD60A'
    var SEV_COLOR = { GITHUB:'#FF453A', AWS:'#FF453A', API:'#FF453A', DB:'#FF453A', PASS:'#FF453A', SSN:'#FF453A', CC:'#FF453A', BANK:'#FF453A', INSID:'#FF453A', EMAIL:'#FF9F0A', PHONE:'#FF9F0A', NAME:'#FF9F0A', ADDR:'#FF9F0A', DOB:'#FF9F0A', MONEY:'#FFD60A', INVOICE:'#FFD60A' }

    var rowsHtml = ''
    for (var type in result.groups) {
      var color = SEV_COLOR[type] || '#888'
      var label = TYPE_LABEL[type] || type
      rowsHtml += '<div style="display:flex;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.06);font-size:12px;"><div style="width:7px;height:7px;border-radius:50%;background:' + color + ';flex-shrink:0"></div><span style="flex:1;color:rgba(255,255,255,0.85)">' + escHtml(label) + '</span><strong style="color:' + color + '">' + result.groups[type] + '</strong></div>'
    }

    var modeStrictStyle = 'background:' + (mode === 'strict' ? 'rgba(10,132,255,0.2)' : 'rgba(255,255,255,0.06)') + ';color:' + (mode === 'strict' ? '#0A84FF' : 'rgba(255,255,255,0.5)') + ';border:1px solid ' + (mode === 'strict' ? 'rgba(10,132,255,0.4)' : 'rgba(255,255,255,0.1)') + ';border-radius:6px;padding:4px 10px;font-size:11px;cursor:pointer;font-family:inherit;font-weight:600'
    var modePersonalStyle = 'background:' + (mode === 'personalized' ? 'rgba(48,209,88,0.2)' : 'rgba(255,255,255,0.06)') + ';color:' + (mode === 'personalized' ? '#30D158' : 'rgba(255,255,255,0.5)') + ';border:1px solid ' + (mode === 'personalized' ? 'rgba(48,209,88,0.4)' : 'rgba(255,255,255,0.1)') + ';border-radius:6px;padding:4px 10px;font-size:11px;cursor:pointer;font-family:inherit;font-weight:600'
    var modeHelp = mode === 'strict' ? 'AI sees tokens only. Max privacy. Generic responses.' : 'AI sees tokens; real values restored in responses on your screen.'

    var wrap = document.createElement('div')
    wrap.id = 'gc-overlay'
    wrap.style.cssText = 'position:fixed;top:0;left:0;right:0;bottom:0;z-index:2147483647;pointer-events:none;'
    wrap.innerHTML =
      '<div style="position:absolute;bottom:100px;right:20px;width:320px;background:rgba(20,20,22,0.99);backdrop-filter:blur(24px);-webkit-backdrop-filter:blur(24px);border:1.5px solid ' + riskColor + ';border-radius:18px;box-shadow:0 20px 60px rgba(0,0,0,0.85);font-family:-apple-system,sans-serif;overflow:hidden;pointer-events:all;">' +
        '<div style="padding:13px 15px;border-bottom:1px solid rgba(255,255,255,0.07);display:flex;align-items:center;gap:10px">' +
          '<span style="font-size:18px">🛡️</span>' +
          '<div style="flex:1"><div style="font-size:13px;font-weight:700;color:#fff">GC Protect</div><div style="font-size:11px;color:rgba(255,255,255,0.4)">' + escHtml(platform()) + ' · ' + result.count + ' detected</div></div>' +
          '<div style="text-align:right"><div style="font-size:24px;font-weight:800;color:' + riskColor + ';line-height:1">' + result.score + '</div><div style="font-size:9px;color:rgba(255,255,255,0.3);font-weight:600">RISK</div></div>' +
          '<button id="gcX" style="width:26px;height:26px;border-radius:50%;background:rgba(255,255,255,0.08);border:none;color:rgba(255,255,255,0.6);font-size:14px;cursor:pointer;flex-shrink:0">✕</button>' +
        '</div>' +
        '<div style="padding:8px 15px;border-bottom:1px solid rgba(255,255,255,0.05)">' + rowsHtml + '</div>' +
        '<div style="padding:10px 15px 6px;display:flex;align-items:center;gap:6px">' +
          '<span style="font-size:11px;color:rgba(255,255,255,0.5);flex:1">Mode:</span>' +
          '<button id="gcModeStrict" style="' + modeStrictStyle + '">🔒 Strict</button>' +
          '<button id="gcModePersonal" style="' + modePersonalStyle + '">✨ Personal</button>' +
        '</div>' +
        '<div style="padding:0 15px 10px;font-size:10px;color:rgba(255,255,255,0.4);line-height:1.4">' + escHtml(modeHelp) + '</div>' +
        '<div style="padding:0 15px 12px;display:flex;flex-direction:column;gap:7px">' +
          '<button id="gcSend" style="background:#0A84FF;color:#fff;border:none;border-radius:10px;padding:12px;font-size:14px;font-weight:700;cursor:pointer;width:100%;font-family:inherit">🛡 Protect &amp; Send</button>' +
          '<div style="display:flex;gap:6px">' +
            '<button id="gcCancel" style="background:rgba(255,255,255,0.07);color:rgba(255,255,255,0.6);border:none;border-radius:8px;padding:9px;font-size:12px;cursor:pointer;flex:1;font-family:inherit">Cancel</button>' +
            '<button id="gcAnyway" style="background:transparent;color:rgba(255,69,58,0.6);border:1px solid rgba(255,69,58,0.2);border-radius:8px;padding:9px;font-size:11px;cursor:pointer;flex:1;font-family:inherit">Send unprotected</button>' +
          '</div>' +
        '</div>' +
      '</div>'

    document.body.appendChild(wrap)

    document.getElementById('gcX').onclick = function(e) {
      e.stopPropagation(); ignoredText = readBox(box); closeOverlay()
    }
    document.getElementById('gcCancel').onclick = function(e) {
      e.stopPropagation(); ignoredText = readBox(box); closeOverlay()
    }
    document.getElementById('gcModeStrict').onclick = function(e) {
      e.stopPropagation()
      mode = 'strict'
      try { chrome.storage.local.set({ mode: 'strict' }) } catch(err) {}
      showOverlay(result, box)
    }
    document.getElementById('gcModePersonal').onclick = function(e) {
      e.stopPropagation()
      mode = 'personalized'
      try { chrome.storage.local.set({ mode: 'personalized' }) } catch(err) {}
      showOverlay(result, box)
    }
    document.getElementById('gcAnyway').onclick = function(e) {
      e.stopPropagation()
      if (!confirm('Send WITHOUT protection?\n\n' + result.count + ' sensitive field(s) will be exposed to ' + platform() + '.')) return
      ignoredText = readBox(box)
      closeOverlay()
      log({ platform: platform(), score: result.score, count: result.count, action: 'unprotected', mode: mode })
      clickSend()
    }
    document.getElementById('gcSend').onclick = function(e) {
      e.stopPropagation()

      closeOverlay()
      showProofPanel(result)

      var cleanMap = {}
      for (var f of result.entities || []) {
        if (f && f.tok && f.val) cleanMap[f.tok] = f.val
      }
      for (var tok in cleanMap) vault.set(tok, cleanMap[tok])

      var finalPrompt = result.protected

      console.log('%c[GC Protect V3.1.0] Mode:', 'color:#30D158;font-weight:bold', mode)
      console.log('%c[GC Protect V3.1.0] Token map:', 'color:#30D158;font-weight:bold', cleanMap)
      console.log('%c[GC Protect V3.1.0] Final prompt sent to AI:', 'color:#0A84FF;font-weight:bold\n', finalPrompt)

      writeBox(box, finalPrompt)

      log({ platform: platform(), score: result.score, count: result.count, action: 'protected', types: result.types, mode: mode })

      if (mode === 'personalized') watchResponse()

      setTimeout(clickSend, 250)
    }
  }

  function intercept(e) {
    if (!enabled || overlayOpen) return
    var box = findBox()
    if (!box) return
    var text = readBox(box)
    if (!text || text.trim().length < 3 || text === ignoredText) return

    var result = scan(text)
    if (result.count === 0) return

    e.preventDefault()
    e.stopImmediatePropagation()
    if (e.stopPropagation) e.stopPropagation()
    showOverlay(result, box)
  }

  function isFocusInBox(box) {
    var active = document.activeElement
    if (!active) return false
    if (active === box) return true
    if (box.contains && box.contains(active)) return true
    var node = active
    while (node) {
      if (node === box) return true
      node = node.parentElement
    }
    return false
  }

  function attachListeners() {
    document.addEventListener('keydown', function(e) {
      if (e.key !== 'Enter' || e.shiftKey || e.ctrlKey || e.metaKey || overlayOpen) return
      var box = findBox()
      if (!box) return
      if (isFocusInBox(box)) intercept(e)
    }, true)

    document.addEventListener('click', function(e) {
      if (overlayOpen) return
      var t = e.target
      if (!t) return
      var btn = t.closest && t.closest('button, div[role="button"]')
      if (!btn) return
      var lbl = (btn.getAttribute('aria-label') || '').toLowerCase()
      var tid = (btn.getAttribute('data-testid') || '').toLowerCase()
      var typ = (btn.getAttribute('type') || '').toLowerCase()
      if (lbl.indexOf('send') >= 0 || lbl.indexOf('submit') >= 0 || tid.indexOf('send') >= 0 || typ === 'submit') {
        intercept(e)
      }
    }, true)
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', attachListeners)
  } else {
    attachListeners()
  }

  var lastUrl = location.href
  new MutationObserver(function() {
    if (location.href !== lastUrl) {
      lastUrl = location.href
      ignoredText = ''
      CURRENT_PLATFORM = null
    }
  }).observe(document.body, { subtree: true, childList: true })

  console.log('%cGC Protect V3.1.0 — active on ' + platform(), 'color:#30D158;font-weight:bold;background:rgba(48,209,88,0.1);padding:4px 10px;border-radius:8px')

})()
