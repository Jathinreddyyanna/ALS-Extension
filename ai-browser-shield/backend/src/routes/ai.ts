import { Router } from 'express'
import aiExplainRouter from './aiExplain'
import aiDebugRouter from './aiDebug'
import testGeminiRouter from './testGemini'

const router = Router()

router.use('/', aiExplainRouter)
router.use('/debug', aiDebugRouter)
router.use('/test-gemini', testGeminiRouter)

export default router
