import "server-only";
import { hash, verify } from "@node-rs/argon2";

/**
 * Password hashing.
 *
 * **Argon2id, and specifically not bcrypt.** Auth.js does
 * not hash passwords for you - the `authorize` callback owns that, and it must
 * use **Argon2id** so legacy hashes keep verifying. A bcrypt default must not
 * slip in.
 *
 * **Legacy hash compatibility is the load-bearing property.** Legacy hashes came
 * from PHP's `PASSWORD_ARGON2ID`, which emits the standard PHC string
 * (`$argon2id$v=19$m=65536,t=4,p=1$<salt>$<hash>`). Because the encoding carries
 * its own parameters, verification reads them from the stored string rather than
 * from the configuration below - which is why the migration needs no password
 * reset, and why the parameters here apply only to *new* hashes.
 *
 * `@node-rs/argon2` is used rather than `argon2` because it is the
 * drop-in that builds cleanly on serverless. Both are native modules, so any
 * route touching this must run on the Node.js runtime - Argon2 will not run on
 * Edge.
 */

/**
 * Parameters for newly created hashes.
 *
 * These match PHP's `PASSWORD_ARGON2ID` defaults (64 MiB, 4 passes, 1 thread),
 * so a password changed through this application produces a hash
 * indistinguishable from one the legacy system would have written. That keeps a
 * staged cutover - where both systems might briefly run - coherent.
 */
const HASH_OPTIONS = {
  memoryCost: 65536,
  timeCost: 4,
  parallelism: 1,
} as const;

/**
 * A valid Argon2id hash of a value no one knows, used for timing equalisation.
 *
 * Applies a constant-time comparison path (verify against a dummy hash
 * when the user is not found) so response timing does not leak existence.
 * Returning early for an unknown email would make the unknown-email case
 * measurably faster than the wrong-password case, turning the login endpoint
 * into a user-enumeration oracle even though both return the same message.
 *
 * Generated at module load rather than hardcoded: a literal in source would be
 * a fixed target, and the cost is one hash per cold start.
 */
let dummyHashPromise: Promise<string> | undefined;

function getDummyHash(): Promise<string> {
  if (!dummyHashPromise) {
    dummyHashPromise = hash(
      `dummy-${crypto.randomUUID()}-${crypto.randomUUID()}`,
      HASH_OPTIONS,
    );
  }
  return dummyHashPromise;
}

export async function hashPassword(password: string): Promise<string> {
  return hash(password, HASH_OPTIONS);
}

/**
 * Verifies a password against a stored hash.
 *
 * A malformed or unrecognised hash returns `false` rather than throwing: a
 * corrupt row must fail the login, not produce a 500 that tells the caller the
 * row exists.
 */
export async function verifyPassword(
  storedHash: string,
  password: string,
): Promise<boolean> {
  try {
    return await verify(storedHash, password);
  } catch {
    return false;
  }
}

/**
 * Runs a verification even when there is no user, so both branches cost the
 * same. The result is discarded - the caller has already decided to fail.
 */
export async function verifyAgainstDummy(password: string): Promise<void> {
  try {
    await verify(await getDummyHash(), password);
  } catch {
    // Deliberately ignored: this call exists only to consume time.
  }
}
