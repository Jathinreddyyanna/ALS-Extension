export class AppError extends Error {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly details?: unknown;

  public constructor(statusCode: number, code: string, message: string, details?: unknown) {
    super(message);
    this.name = this.constructor.name;
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
  }
}

export class ValidationError extends AppError {
  public constructor(message: string, details?: unknown) {
    super(422, 'validation_error', message, details);
  }
}

export class NotFoundError extends AppError {
  public constructor(message: string, details?: unknown) {
    super(404, 'not_found', message, details);
  }
}

export class RateLimitError extends AppError {
  public constructor(message: string, details?: unknown) {
    super(429, 'rate_limit_exceeded', message, details);
  }
}

export class AiError extends AppError {
  public constructor(message: string, details?: unknown) {
    super(502, 'ai_error', message, details);
  }
}

export class DatabaseError extends AppError {
  public constructor(message: string, details?: unknown) {
    super(503, 'database_error', message, details);
  }
}
