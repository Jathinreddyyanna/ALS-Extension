import { spawn } from 'child_process'
import { resolve, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const root = resolve(__dirname, '..')
const postbuildScript = resolve(__dirname, 'postbuild.mjs')

let postbuildRunning = false
let queued = false

function runPostbuild(reason = 'vite build complete') {
  if (postbuildRunning) {
    queued = true
    return
  }

  postbuildRunning = true
  console.log(`[dev-watch] Running postbuild (${reason})...`)

  const child = spawn(process.execPath, [postbuildScript], {
    cwd: root,
    stdio: 'inherit',
  })

  child.on('exit', () => {
    postbuildRunning = false
    if (queued) {
      queued = false
      runPostbuild('queued build')
    }
  })
}

const vite = spawn('npx', ['vite', 'build', '--watch'], {
  cwd: root,
  shell: true,
  stdio: ['inherit', 'pipe', 'pipe'],
})

function handleChunk(text) {
  process.stdout.write(text)
  if (text.includes('built in ')) {
    runPostbuild()
  }
}

vite.stdout.on('data', (chunk) => {
  handleChunk(chunk.toString())
})

vite.stderr.on('data', (chunk) => {
  process.stderr.write(chunk.toString())
})

vite.on('exit', (code) => {
  process.exit(code ?? 0)
})

