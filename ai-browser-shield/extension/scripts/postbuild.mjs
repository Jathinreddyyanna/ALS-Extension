// Runs after vite build — copies static files Chrome needs into dist/
import { copyFileSync, mkdirSync, existsSync, readFileSync, writeFileSync } from 'fs'
import { resolve, dirname } from 'path'
import { fileURLToPath } from 'url'
import { build } from 'esbuild'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = resolve(__dirname, '..')
const dist = resolve(root, 'dist')

function copy(src, dest) {
  const destDir = dirname(dest)
  if (!existsSync(destDir)) mkdirSync(destDir, { recursive: true })
  copyFileSync(src, dest)
  console.log(`  ✓ ${dest.replace(root, '')}`)
}

console.log('\n📦 Post-build: copying static assets...')

// manifest.json → dist/manifest.json
copy(resolve(root, 'manifest.json'), resolve(dist, 'manifest.json'))

// icons → dist/
copy(resolve(root, 'public/icon48.png'),  resolve(dist, 'icon48.png'))
copy(resolve(root, 'public/icon128.png'), resolve(dist, 'icon128.png'))

// rules/adblock.json → dist/rules/adblock.json
copy(resolve(root, 'rules/adblock.json'), resolve(dist, 'rules/adblock.json'))

// Rebundle the content script as a single classic script.
// Chrome content scripts cannot use top-level ES module imports here.
await build({
  entryPoints: [resolve(root, 'src/content/index.ts')],
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: ['chrome114'],
  outfile: resolve(dist, 'content.js'),
  sourcemap: false,
  logLevel: 'silent',
})
console.log('  ✓ /dist/content.js (rebundled as standalone content script)')

// Fix popup.html path — vite outputs to dist/src/popup/index.html
// Chrome needs it at dist/popup.html
const popupSrc  = resolve(dist, 'src/popup/index.html')
const popupDest = resolve(dist, 'popup.html')
if (existsSync(popupSrc)) {
  let html = readFileSync(popupSrc, 'utf-8')
  // Fix asset paths (../../assets/ → assets/)
  html = html.replace(/\.\.\/\.\.\/assets\//g, 'assets/')
  html = html.replace(/\.\.\/assets\//g, 'assets/')
  writeFileSync(popupDest, html)
  console.log('  ✓ /dist/popup.html (moved from src/popup/index.html)')
}

console.log('\n✅ dist/ is ready to load in Chrome!\n')
console.log('Structure:')
console.log('  dist/manifest.json')
console.log('  dist/background.js')
console.log('  dist/content.js')
console.log('  dist/popup.html')
console.log('  dist/popup.js')
console.log('  dist/icon48.png')
console.log('  dist/icon128.png')
console.log('  dist/rules/adblock.json')
