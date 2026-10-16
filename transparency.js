// GC Protect — Transparency Panel Logic
// Shows the user exactly what's stored, where, and lets them control it

async function loadData() {
  // BROWSER MEMORY - fetch from active tab's content script
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    const response = await chrome.tabs.sendMessage(tab.id, { type: 'GET_VAULT_STATE' })
    if (response && response.vault) {
      document.getElementById('vaultCount').textContent = response.vault.length + ' item' + (response.vault.length !== 1 ? 's' : '')
      window._vault = response.vault
    }
  } catch (e) {
    document.getElementById('vaultCount').textContent = 'Not on AI tab'
  }

  // CHROME LOCAL STORAGE - direct read
  const local = await chrome.storage.local.get(null)
  const log = local.log || local.auditLog || []
  const settings = {}
  if ('enabled' in local) settings.enabled = local.enabled
  if ('customEntities' in local) settings.customEntities = local.customEntities

  document.getElementById('logCount').textContent = log.length
  document.getElementById('settingsCount').textContent = Object.keys(settings).length

  window._local = { log, settings }

  // SUPABASE - would fetch via authenticated API
  // For now, show placeholder that fetches from your API endpoint
  fetchCloudCounts()
}

async function fetchCloudCounts() {
  try {
    // In production, this hits your Supabase edge function
    // For now, use local log as proxy for cloud metadata count
    const local = await chrome.storage.local.get(['log', 'auditLog'])
    const count = (local.log || local.auditLog || []).length
    document.getElementById('cloudCount').textContent = count
    document.getElementById('feedbackCount').textContent = '0'
  } catch (e) {
    document.getElementById('cloudCount').textContent = 'Login required'
    document.getElementById('feedbackCount').textContent = '—'
  }
}

function toggleVault() {
  const reveal = document.getElementById('vaultReveal')
  if (reveal.classList.contains('show')) {
    reveal.classList.remove('show')
    return
  }

  if (!window._vault || window._vault.length === 0) {
    reveal.innerHTML = '<div style="text-align:center;color:rgba(255,255,255,0.4);padding:10px">Vault is empty. Open ChatGPT/Claude and protect a prompt to see contents here.</div>'
  } else {
    reveal.innerHTML = window._vault.map(function(pair) {
      return '<div class="row"><span class="tok">' + escapeHtml(pair[0]) + '</span><span class="arrow">→</span><span class="val">' + escapeHtml(pair[1]) + '</span></div>'
    }).join('')
  }
  reveal.classList.add('show')
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, function(c) {
    return { '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' }[c]
  })
}

async function clearVault() {
  if (!confirm('Destroy the session vault now?\n\nThis will remove all token-to-value mappings. AI responses may show tokens instead of real names until you protect another prompt.')) return
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
    await chrome.tabs.sendMessage(tab.id, { type: 'CLEAR_VAULT' })
    document.getElementById('vaultCount').textContent = '0'
    document.getElementById('vaultReveal').classList.remove('show')
    showNotification('Vault destroyed', '#30D158')
  } catch (e) {
    showNotification('Could not reach tab — reload it first', '#FF9F0A')
  }
}

async function exportLocal() {
  const data = window._local || {}
  const json = JSON.stringify(data, null, 2)
  const blob = new Blob([json], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'gcprotect-local-data-' + new Date().toISOString().split('T')[0] + '.json'
  a.click()
  showNotification('Exported ' + (data.log ? data.log.length : 0) + ' entries', '#30D158')
}

async function deleteLocal() {
  if (!confirm('Delete ALL local data on this device?\n\nThis removes:\n• Your audit log (' + (window._local.log ? window._local.log.length : 0) + ' entries)\n• Your preferences\n\nThis cannot be undone. Your account and cloud data are separate.')) return
  await chrome.storage.local.clear()
  showNotification('All local data deleted', '#30D158')
  setTimeout(function() { loadData() }, 500)
}

function viewCloud() {
  chrome.tabs.create({ url: 'https://www.gcprotect.tech/dashboard' })
}

function deleteAccount() {
  if (!confirm('Delete your GC Protect account?\n\nThis will:\n• Remove all your cloud data permanently\n• Cancel any active subscription\n• Log you out of the extension\n\nType DELETE in the next prompt to confirm.')) return
  const confirmation = prompt('Type DELETE to confirm account deletion:')
  if (confirmation !== 'DELETE') {
    showNotification('Cancelled — account not deleted', '#FF9F0A')
    return
  }
  chrome.tabs.create({ url: 'https://www.gcprotect.tech/account/delete' })
}

function showNotification(msg, color) {
  const existing = document.getElementById('notify')
  if (existing) existing.remove()
  const n = document.createElement('div')
  n.id = 'notify'
  n.textContent = msg
  n.style.cssText = 'position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:rgba(20,20,22,0.98);border:1px solid ' + color + '60;color:' + color + ';padding:10px 20px;border-radius:20px;font-size:12px;font-weight:600;box-shadow:0 8px 24px rgba(0,0,0,0.5);z-index:100'
  document.body.appendChild(n)
  setTimeout(function() { n.remove() }, 3000)
}

loadData()
