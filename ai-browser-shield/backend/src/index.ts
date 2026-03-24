import 'dotenv/config'
import app from './app'
import { prisma } from './db/client'
import { loadModelMetadata, getModelPerformanceSummary, validateModelMetadata } from './services/modelMetadata'

const PORT = parseInt(process.env.PORT || '3001')
const NODE_MAJOR = Number.parseInt(process.versions.node.split('.')[0] || '0', 10)
const isNoDb = () => process.env.NO_DB === 'true'

function formatStartupError(err: unknown) {
  if (err instanceof Error) {
    return {
      name: err.name,
      message: err.message,
      stack: err.stack,
      cause: 'cause' in err ? err.cause : undefined,
    }
  }

  return err
}

async function start() {
  try {
    if (NODE_MAJOR >= 24) {
      throw new Error(
        `Node.js ${process.versions.node} detected. This backend currently uses Prisma 5.x and should be run on Node 20 or 22 LTS.`
      )
    }

    // ── Load ML Model Metadata ───────────────────────────────────────────────────
    console.log('🤖 Loading ML model metadata...')
    loadModelMetadata()
    const validation = validateModelMetadata()
    if (!validation.valid) {
      console.warn('⚠️  Model metadata validation issues:', validation.issues)
    }
    console.log(getModelPerformanceSummary())

    if (isNoDb()) {
      console.log('Database disabled (NO_DB=true)')
    } else {
      try {
        await prisma.$connect()
        console.log('Database connected')
      } catch (err) {
        console.warn('Database unavailable. Continuing with NO_DB=true mode.')
        process.env.NO_DB = 'true'
        console.warn(formatStartupError(err))
      }
    }

    const tryListen = (port: number) => {
      const server = app.listen(port, () => {
        console.log(`AI Browser Shield API running on http://localhost:${port}`)
        console.log(`Health check: http://localhost:${port}/api/v1/health`)
        console.log(`Environment: ${process.env.NODE_ENV || 'development'}`)
      })

      server.on('error', (err: NodeJS.ErrnoException) => {
        if (err.code === 'EADDRINUSE') {
          const nextPort = port + 1
          console.warn(`Port ${port} is in use. Trying ${nextPort}...`)
          tryListen(nextPort)
          return
        }
        throw err
      })
    }

    tryListen(PORT)
  } catch (err) {
    console.error('Failed to start server:', formatStartupError(err))
    process.exit(1)
  }
}

start()

process.on('SIGTERM', async () => {
  if (!isNoDb()) await prisma.$disconnect()
  process.exit(0)
})
