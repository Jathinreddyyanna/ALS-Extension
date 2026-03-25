import { PrismaClient } from '@prisma/client';
import { logger } from '../utils/logger';

declare global {
  // eslint-disable-next-line no-var
  var __ABS_PRISMA__: PrismaClient | undefined;
  // eslint-disable-next-line no-var
  var __ABS_DB_AVAILABLE__: boolean | undefined;
}

export const prisma = global.__ABS_PRISMA__ ?? new PrismaClient({
  log: process.env.NODE_ENV === 'development' ? ['query', 'error'] : []
});

if (!global.__ABS_PRISMA__) {
  global.__ABS_PRISMA__ = prisma;
}

if (typeof global.__ABS_DB_AVAILABLE__ !== 'boolean') {
  global.__ABS_DB_AVAILABLE__ = false;
}

export const isDatabaseAvailable = (): boolean => global.__ABS_DB_AVAILABLE__ === true;

export const connectDatabase = async (): Promise<boolean> => {
  if (process.env.NO_DB === 'true') {
    global.__ABS_DB_AVAILABLE__ = false;
    return false;
  }
  try {
    await prisma.$connect();
    global.__ABS_DB_AVAILABLE__ = true;
    return true;
  } catch (error) {
    global.__ABS_DB_AVAILABLE__ = false;
    logger.error({ err: error }, 'database connection failed');
    return false;
  }
};

export const disconnectDatabase = async (): Promise<void> => {
  global.__ABS_DB_AVAILABLE__ = false;
  await prisma.$disconnect();
};

export const isPrismaKnownError = (error: unknown, code: string): boolean =>
  typeof error === 'object' &&
  error !== null &&
  'code' in error &&
  (error as { code?: string }).code === code;