import { PrismaClient } from '@prisma/client'

const globalForPrisma = globalThis as unknown as { prisma: PrismaClient }
const NO_DB = process.env.NO_DB === 'true'

export const prisma = NO_DB
  ? ({} as PrismaClient)
  : (globalForPrisma.prisma || new PrismaClient({
      log: process.env.NODE_ENV === 'development' ? ['query', 'error'] : ['error'],
    }))

if (!NO_DB && process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma
