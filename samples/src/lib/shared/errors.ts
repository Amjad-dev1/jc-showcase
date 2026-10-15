/**
 * The error contract.
 *
 * Every error the API returns - public or admin, route handler or Server Action
 * - is shaped by this module. Two rules justify centralising it:
 *
 *  1. **Never return database exception text to a client.** Legacy rendered raw
 *     driver errors into the HTML response, leaking schema details. The
 *     only way to guarantee that does not recur is for the serialiser to be the
 *     single exit path, and for it to emit a fixed message per code rather than
 *     whatever a caught exception happened to carry.
 *  2. Messages are part of the contract. Several are quoted verbatim
 *     because the frontend displays them and legacy users recognise them, so
 *     they live in the table below rather than at each call site.
 */

export const ERROR_CODES = {
  INVALID_INPUT: "INVALID_INPUT",
  VALIDATION_ERROR: "VALIDATION_ERROR",
  INVALID_CREDENTIALS: "INVALID_CREDENTIALS",
  OLD_PASSWORD_INCORRECT: "OLD_PASSWORD_INCORRECT",
  UNAUTHORIZED: "UNAUTHORIZED",
  FORBIDDEN: "FORBIDDEN",
  RECAPTCHA_FAILED: "RECAPTCHA_FAILED",
  INVALID_CALLBACK: "INVALID_CALLBACK",
  EVENT_NOT_FOUND: "EVENT_NOT_FOUND",
  NOT_FOUND: "NOT_FOUND",
  REGISTRATION_CLOSED: "REGISTRATION_CLOSED",
  DUPLICATE_EMAIL_FOR_EVENT: "DUPLICATE_EMAIL_FOR_EVENT",
  RESOURCE_IN_USE: "RESOURCE_IN_USE",
  DUPLICATE_RESOURCE: "DUPLICATE_RESOURCE",
  PAYMENT_NOT_AVAILABLE: "PAYMENT_NOT_AVAILABLE",
  GATEWAY_ERROR: "GATEWAY_ERROR",
  RATE_LIMITED: "RATE_LIMITED",
  EMAIL_SEND_FAILED: "EMAIL_SEND_FAILED",
  INTERNAL_ERROR: "INTERNAL_ERROR",
} as const;

export type ErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

/**
 * Status and default message per code.
 *
 * `RECAPTCHA_FAILED` keeps its legacy name even though bot protection is now
 * Cloudflare Turnstile - the code name is pinned explicitly for API stability,
 * so renaming it would be a breaking change for no benefit.
 */
const ERROR_TABLE: Record<ErrorCode, { status: number; message: string }> = {
  INVALID_INPUT: { status: 400, message: "Invalid input." },
  VALIDATION_ERROR: { status: 400, message: "Validation failed." },
  INVALID_CREDENTIALS: { status: 401, message: "Invalid credentials!" },
  OLD_PASSWORD_INCORRECT: {
    status: 401,
    message: "Old password is incorrect! Please revise your inputs.",
  },
  UNAUTHORIZED: { status: 401, message: "Authentication required." },
  FORBIDDEN: { status: 403, message: "You do not have access to this resource." },
  RECAPTCHA_FAILED: {
    status: 403,
    message: "Could not send message! This device failed the bot-protection check.",
  },
  INVALID_CALLBACK: { status: 403, message: "Invalid or expired payment session." },
  EVENT_NOT_FOUND: { status: 404, message: "Event not found." },
  NOT_FOUND: { status: 404, message: "Not found." },
  REGISTRATION_CLOSED: {
    status: 409,
    message: "The registration for this event is closed.",
  },
  DUPLICATE_EMAIL_FOR_EVENT: {
    status: 409,
    message:
      "A registration was already made with this e-mail address. Please choose another e-mail.",
  },
  RESOURCE_IN_USE: {
    status: 409,
    message: "Cannot delete: this record is referenced by other data.",
  },
  DUPLICATE_RESOURCE: { status: 409, message: "This record already exists." },
  PAYMENT_NOT_AVAILABLE: {
    status: 409,
    message: "Online payment is not available for this event.",
  },
  GATEWAY_ERROR: {
    status: 502,
    message: "The payment gateway could not be reached. Please try again.",
  },
  RATE_LIMITED: { status: 429, message: "Too many requests. Please try again shortly." },
  EMAIL_SEND_FAILED: {
    status: 500,
    message: "Could not send message! Please try again later...",
  },
  INTERNAL_ERROR: { status: 500, message: "An unexpected error occurred." },
};

/** A single field-level validation problem, per the `details` array. */
export interface ErrorDetail {
  field: string;
  message: string;
}

export interface ErrorEnvelope {
  error: {
    code: ErrorCode;
    message: string;
    details?: ErrorDetail[];
  };
}

/**
 * The one error type the application throws.
 *
 * Anything thrown that is *not* an `AppError` is treated as a bug and collapsed
 * to `INTERNAL_ERROR` by the handler wrapper, which is what keeps driver text
 * out of responses without every call site having to remember to catch.
 */
export class AppError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly details?: ErrorDetail[];

  constructor(code: ErrorCode, message?: string, details?: ErrorDetail[]) {
    const entry = ERROR_TABLE[code];
    super(message ?? entry.message);
    this.name = "AppError";
    this.code = code;
    this.status = entry.status;
    this.details = details;
  }

  toEnvelope(): ErrorEnvelope {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.details?.length ? { details: this.details } : {}),
      },
    };
  }
}

/** Convenience constructors for the codes used most, to keep call sites short. */
export const errors = {
  invalidInput: (details?: ErrorDetail[], message?: string) =>
    new AppError(ERROR_CODES.INVALID_INPUT, message, details),
  validation: (details?: ErrorDetail[], message?: string) =>
    new AppError(ERROR_CODES.VALIDATION_ERROR, message, details),
  unauthorized: () => new AppError(ERROR_CODES.UNAUTHORIZED),
  forbidden: () => new AppError(ERROR_CODES.FORBIDDEN),
  eventNotFound: () => new AppError(ERROR_CODES.EVENT_NOT_FOUND),
  notFound: (message?: string) => new AppError(ERROR_CODES.NOT_FOUND, message),
  registrationClosed: () => new AppError(ERROR_CODES.REGISTRATION_CLOSED),
  duplicateEmail: () =>
    new AppError(ERROR_CODES.DUPLICATE_EMAIL_FOR_EVENT, undefined, [
      { field: "email", message: "Already registered for this event" },
    ]),
  resourceInUse: (message?: string) => new AppError(ERROR_CODES.RESOURCE_IN_USE, message),
  duplicateResource: (field: string, message?: string) =>
    new AppError(ERROR_CODES.DUPLICATE_RESOURCE, message, [
      { field, message: message ?? "Already exists" },
    ]),
  rateLimited: () => new AppError(ERROR_CODES.RATE_LIMITED),
  internal: () => new AppError(ERROR_CODES.INTERNAL_ERROR),
} as const;

export function statusForCode(code: ErrorCode): number {
  return ERROR_TABLE[code].status;
}

export function messageForCode(code: ErrorCode): string {
  return ERROR_TABLE[code].message;
}
