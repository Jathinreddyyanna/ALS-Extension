const statusEl = document.getElementById('status') as HTMLDivElement
const geminiKeyInput = document.getElementById('geminiKey') as HTMLInputElement
const apiBaseUrlInput = document.getElementById('apiBaseUrl') as HTMLInputElement
const saveBtn = document.getElementById('saveBtn') as HTMLButtonElement
const clearBtn = document.getElementById('clearBtn') as HTMLButtonElement

function setStatus(message: string, type: 'ok' | 'err' | '') {
  statusEl.textContent = message
  statusEl.className = 'status' + (type ? ` ${type}` : '')
}

function readSettings() {
  chrome.storage.sync.get(['geminiApiKey', 'apiBaseUrl'], (r) => {
    geminiKeyInput.value = r.geminiApiKey || ''
    apiBaseUrlInput.value = r.apiBaseUrl || ''
  })
}

saveBtn.addEventListener('click', () => {
  const geminiApiKey = geminiKeyInput.value.trim()
  const apiBaseUrl = apiBaseUrlInput.value.trim().replace(/\/+$/, '')

  if (!geminiApiKey) {
    setStatus('Gemini API key is required.', 'err')
    return
  }

  chrome.storage.sync.set({ geminiApiKey, apiBaseUrl }, () => {
    setStatus('Settings saved.', 'ok')
    setTimeout(() => setStatus('', ''), 2000)
  })
})

clearBtn.addEventListener('click', () => {
  chrome.storage.local.get(null, (items) => {
    const safeItems = items && typeof items === 'object' ? items : {}
    const keys = Object.keys(safeItems)
    const toRemove = keys.filter(k => k === 'threatHistory' || k.startsWith('score:'))
    chrome.storage.local.remove(toRemove, () => {
      setStatus('Cache cleared.', 'ok')
      setTimeout(() => setStatus('', ''), 2000)
    })
  })
})

readSettings()
