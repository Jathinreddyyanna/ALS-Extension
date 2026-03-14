import type { PageContextSnapshot } from '../types'

function collectText(selector: string, limit: number): string[] {
  return Array.from(document.querySelectorAll(selector))
    .map(node => (node.textContent || '').replace(/\s+/g, ' ').trim())
    .filter(Boolean)
    .slice(0, limit)
}

export function extractPageContext(): PageContextSnapshot {
  const title = document.title.trim().slice(0, 120)
  const headings = collectText('h1, h2, h3', 6).map(text => text.slice(0, 120))
  const actionTexts = collectText('button, [role="button"], input[type="submit"], a', 8).map(text => text.slice(0, 80))

  const formSignals = Array.from(document.querySelectorAll('input, textarea, select'))
    .map(node => {
      const input = node as HTMLInputElement
      const bits = [
        input.type,
        input.name,
        input.id,
        input.placeholder,
        input.getAttribute('autocomplete') || '',
        input.labels?.[0]?.textContent || '',
      ]
      return bits.join(' ').replace(/\s+/g, ' ').trim()
    })
    .filter(Boolean)
    .slice(0, 8)
    .map(text => text.slice(0, 120))

  const bodyPreview = (document.body?.innerText || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 1000)

  return {
    title,
    headings,
    bodyPreview,
    formSignals,
    actionTexts,
  }
}
