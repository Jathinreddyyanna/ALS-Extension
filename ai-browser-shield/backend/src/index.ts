import 'dotenv/config'
import app from './app'
import { prisma } from './db/client'
import { serverConfig } from './config'

async function start() {
  try {
    // Test DB connection
    await prisma.$connect()
    console.log('✅ Database connected')

    app.listen(serverConfig.port, () => {
      console.log(`🚀 AI Browser Shield API running on http://localhost:${serverConfig.port}`)
      console.log(`📊 Health check: http://localhost:${serverConfig.port}/api/v1/health`)
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
