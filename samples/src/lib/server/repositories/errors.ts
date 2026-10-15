import "server-only";
import { AppError, ERROR_CODES } from "@/lib/shared/errors";

/**
 * Translating PostgreSQL errors into the error envelope.
 *
 * This is the boundary that guarantees "Never return database exception text to
 * a client" and corrects the legacy defect where raw exception text was
 * rendered straight into the HTML response, leaking schema details.
 *
 * Constraint violations are mapped by *name*, not by parsing the message. The
 * names are declared in the DDL, so the mapping is stable across Postgres
 * versions and locales, and an unrecognised violation falls through to a
 * generic 500 rather than guessing.
 */

const PG_UNIQUE_VIOLATION = "23505";
const PG_FOREIGN_KEY_VIOLATION = "23503";
/**
 * `restrict_violation` - raised instead of 23503 when `ON DELETE RESTRICT`
 * blocks a delete. Both mean "still referenced", which maps to
 * `409 RESOURCE_IN_USE`.
 */
const PG_RESTRICT_VIOLATION = "23001";
const PG_CHECK_VIOLATION = "23514";

interface PgErrorLike {
  code?: string;
  constraint?: string;
  detail?: string;
}

/** Drizzle wraps driver errors; the real one is on `cause`. */
export function asPgError(error: unknown): PgErrorLike | null {
  if (!error || typeof error !== "object") return null;

  const cause = (error as { cause?: unknown }).cause;
  if (cause && typeof cause === "object" && "code" in cause) return cause as PgErrorLike;
  if ("code" in error) return error as PgErrorLike;
  return null;
}

/** Named unique constraints, mapped to the user-facing failure they represent. */
const UNIQUE_CONSTRAINT_ERRORS: Record<string, () => AppError> = {
  uq_registrations_event_email: () =>
    new AppError(ERROR_CODES.DUPLICATE_EMAIL_FOR_EVENT, undefined, [
      { field: "email", message: "Already registered for this event" },
    ]),
  uq_registrations_order_id: () =>
    new AppError(ERROR_CODES.DUPLICATE_RESOURCE, "This order has already been recorded.", [
      { field: "orderId", message: "Already used" },
    ]),
  uq_potential_customers: () =>
    new AppError(ERROR_CODES.DUPLICATE_RESOURCE, "This lead was already captured.", [
      { field: "email", message: "Already captured" },
    ]),
  uq_event_topics: () =>
    new AppError(ERROR_CODES.DUPLICATE_RESOURCE, "This topic already exists for that pair.", [
      { field: "topic", message: "Already exists" },
    ]),
  idx_cities_name_lower: () =>
    new AppError(ERROR_CODES.DUPLICATE_RESOURCE, "A city with that name already exists.", [
      { field: "name", message: "Already exists" },
    ]),
  idx_admin_users_email_lower: () =>
    new AppError(ERROR_CODES.DUPLICATE_RESOURCE, "An account with that email already exists.", [
      { field: "email", message: "Already exists" },
    ]),
  event_names_name_unique: () =>
    new AppError(ERROR_CODES.DUPLICATE_RESOURCE, "An event name with that name already exists.", [
      { field: "name", message: "Already exists" },
    ]),
  event_types_name_unique: () =>
    new AppError(ERROR_CODES.DUPLICATE_RESOURCE, "An event type with that name already exists.", [
      { field: "name", message: "Already exists" },
    ]),
  admin_users_email_unique: () =>
    new AppError(ERROR_CODES.DUPLICATE_RESOURCE, "An account with that email already exists.", [
      { field: "email", message: "Already exists" },
    ]),
};

/** CHECK constraints, mapped to the rule the input broke. */
const CHECK_CONSTRAINT_ERRORS: Record<string, () => AppError> = {
  chk_events_dates: () =>
    new AppError(ERROR_CODES.VALIDATION_ERROR, "End date must not be before the start date.", [
      { field: "endsAt", message: "Must be on or after the start date" },
    ]),
  chk_events_partner_cut: () =>
    new AppError(ERROR_CODES.VALIDATION_ERROR, "Partner cut must be between 0 and 100.", [
      { field: "partnerCutPct", message: "Must be between 0 and 100" },
    ]),
  chk_events_counts: () =>
    new AppError(ERROR_CODES.VALIDATION_ERROR, "Amounts and counters must not be negative.", []),
  chk_event_types_hours: () =>
    new AppError(ERROR_CODES.VALIDATION_ERROR, "Hours must be at least 1.", [
      { field: "hours", message: "Must be at least 1" },
    ]),
  chk_event_types_display_fee: () =>
    new AppError(ERROR_CODES.VALIDATION_ERROR, "Display fee must not be negative.", [
      { field: "displayFee", message: "Must be zero or greater" },
    ]),
  chk_event_types_gateway_fee: () =>
    new AppError(ERROR_CODES.VALIDATION_ERROR, "Gateway fee must not be negative.", [
      { field: "gatewayFee", message: "Must be zero or greater" },
    ]),
};

/**
 * Converts a database error into an `AppError`, or returns null when it is not
 * a constraint violation we recognise - in which case the caller should let it
 * propagate to the generic 500 handler, which logs the detail server-side and
 * tells the client nothing.
 */
export function translatePgError(error: unknown): AppError | null {
  const pgError = asPgError(error);
  if (!pgError?.code) return null;

  const constraint = pgError.constraint ?? "";

  if (pgError.code === PG_UNIQUE_VIOLATION) {
    const mapped = UNIQUE_CONSTRAINT_ERRORS[constraint];
    return mapped
      ? mapped()
      : new AppError(ERROR_CODES.DUPLICATE_RESOURCE, "This record already exists.");
  }

  if (pgError.code === PG_CHECK_VIOLATION) {
    const mapped = CHECK_CONSTRAINT_ERRORS[constraint];
    return mapped ? mapped() : new AppError(ERROR_CODES.VALIDATION_ERROR);
  }

  if (
    pgError.code === PG_FOREIGN_KEY_VIOLATION ||
    pgError.code === PG_RESTRICT_VIOLATION
  ) {
    return new AppError(ERROR_CODES.RESOURCE_IN_USE);
  }

  return null;
}

/**
 * Runs a database operation, re-throwing constraint violations as `AppError`s.
 *
 * Application code still checks the common cases first so it can return a
 * friendly message before touching the database, but that check is a race:
 * between the SELECT and the INSERT another request may have won. This wrapper
 * is what makes losing that race produce the same clean 409 rather than a 500.
 */
export async function withPgErrors<T>(operation: () => Promise<T>): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    const translated = translatePgError(error);
    if (translated) throw translated;
    throw error;
  }
}
