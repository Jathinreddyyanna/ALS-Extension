import app from './app'
import { prisma } from './db/client'

const PORT = parseInt(process.env.PORT || '3001')

async function start() {
  try {
    // Test DB connection
    await prisma.$connect()
    console.log('✅ Database connected')

    app.listen(PORT, () => {
      console.log(`🚀 AI Browser Shield API running on http://localhost:${PORT}`)
      console.log(`📊 Health check: http://localhost:${PORT}/api/v1/health`)
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`)
    })
  } catch (err) {
    console.error('❌ Failed to start server:', err)
    process.exit(1)
  }
}

start()

process.on('SIGTERM', async () => {
  await prisma.$disconnect()
  process.exit(0)
})
