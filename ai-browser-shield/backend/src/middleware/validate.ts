import { Request, Response, NextFunction } from 'express'
import { ZodSchema, ZodError } from 'zod'

export function validate(schema: ZodSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const result = schema.safeParse(req.body)
    if (!result.success) {
      const errors = (result.error as ZodError).errors.map(e => ({
        field: e.path.join('.'),
        message: e.message,
        code: e.code,
      }))
      return res.status(422).json({
        type: 'https://aibrowsershield.dev/errors/validation',
        title: 'Validation Error',
        status: 422,
        detail: `${errors.length} validation error(s) found`,
        errors,
      })
    }
    req.body = result.data
    next()
  }
}
