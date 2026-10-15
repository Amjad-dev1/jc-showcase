import { z } from "zod";
import { TITLES } from "../constants/enums";
import { emailSchema, idSchema, optionalText } from "./common";

/**
 * Request schemas for the public API.
 *
 * The error messages are fixed by the validation tables, because they
 * are user-facing strings the legacy site displayed and returning customers
 * recognise: "Name is too short or empty!", "Mobile is too short or empty!",
 * "Please enter a valid email!".
 *
 * These schemas are shared with the client forms so the browser applies the same
 * rules - but the browser copy is a convenience only. The server validates
 * independently on every request.
 */

/** The canonical title list, plus the empty "(None)" option. */
const titleSchema = z
  .union([z.enum(TITLES), z.literal(""), z.null()])
  // `.optional()` before `.transform()` - see the note on `optionalText`.
  .optional()
  .transform((value) => (value === "" || value == null ? null : value));

export const checkEmailSchema = z.object({
  eventId: idSchema,
  email: emailSchema,
});

export type CheckEmailInput = z.infer<typeof checkEmailSchema>;

/**
 * Lead capture. Only `eventId` and `email` are required - the whole point
 * is to salvage a partially-filled form.
 */
export const potentialCustomerSchema = z.object({
  eventId: idSchema,
  email: emailSchema,
  title: titleSchema,
  firstName: optionalText(75),
  lastName: optionalText(75),
  mobile: optionalText(100),
});

export type PotentialCustomerInput = z.infer<typeof potentialCustomerSchema>;

/**
 * Registration.
 *
 * The name check is on the **combined** first and last name, per the
 * rule `(firstName + ' ' + lastName)` length >= 2, so a single-character first
 * name with a real surname passes while two blank fields do not. Applying the
 * rule to each field separately would reject legitimate short names.
 *
 * Note what this schema does **not** accept: `orderId`, `paymentState`, or any
 * paid flag - accepting an order ID on a public endpoint would let
 * any caller mark themselves paid by inventing one. Paid registrations are
 * created exclusively by server-side finalization.
 */
export const registrationSchema = z
  .object({
    eventId: idSchema,
    title: titleSchema,
    firstName: z.string().trim().max(75).default(""),
    lastName: z.string().trim().max(75).default(""),
    mobile: z
      .string()
      .trim()
      .min(8, "Mobile is too short or empty!")
      .max(100, "Mobile is too short or empty!"),
    mobileIntl: optionalText(100),
    email: emailSchema,
    // `notes` IS still accepted, and is stored in the notes column.
    notes: optionalText(500),
  })
  .transform((value) => ({
    ...value,
    fullName: `${value.firstName} ${value.lastName}`.trim(),
  }))
  .refine((value) => value.fullName.length >= 2, {
    message: "Name is too short or empty!",
    path: ["firstName"],
  });

export type RegistrationInput = z.infer<typeof registrationSchema>;

/** Contact form. */
export const contactRequestSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, "Name is too short or empty!")
    .max(150, "Name is too short or empty!"),
  email: emailSchema,
  message: z
    .string()
    .trim()
    .min(3, "Too short message! Please enter something.")
    .max(2000, "Message is too long."),
  // Optional in the schema so the endpoint can distinguish "absent" from
  // "invalid" and return the bot-protection error rather than a field
  // validation error.
  turnstileToken: z.string().optional(),
});

export type ContactRequestInput = z.infer<typeof contactRequestSchema>;

/** Payment session initiation - the full registration payload. */
export const paymentSessionSchema = registrationSchema;

export type PaymentSessionInput = z.infer<typeof paymentSessionSchema>;

/**
 * Payment verification.
 *
 * The token and **nothing else that matters**. The outcome, amount and order ID
 * are never accepted from the client - they come from MPGS's own API.
 */
export const paymentVerifySchema = z.object({
  checkoutToken: z.string().min(1),
});

export type PaymentVerifyInput = z.infer<typeof paymentVerifySchema>;
