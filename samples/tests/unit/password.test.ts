import { describe, expect, it } from "vitest";
import {
  hashPassword,
  verifyAgainstDummy,
  verifyPassword,
} from "@/lib/server/auth/password";

/**
 * Password hashing and the legacy-hash migration assumption.
 *
 * This was the riskiest assumption in the whole migration: if `argon2.verify()`
 * did not accept a PHP `PASSWORD_ARGON2ID` hash carried over from the legacy
 * database, every admin would need a password reset at cutover.
 *
 * The fixture below is a real hash emitted by PHP's
 * `password_hash($pw, PASSWORD_ARGON2ID)` - generated with the PHP binary, not
 * hand-written - so this test is the actual proof, not a restatement of the
 * assumption. If a future dependency change breaks PHC-string compatibility,
 * this fails and the cutover plan is known to need revisiting before release.
 */

/** `password_hash('CorrectHorse!42', PASSWORD_ARGON2ID)` under PHP 8. */
const PHP_ARGON2ID_HASH =
  "$argon2id$v=19$m=65536,t=4,p=1$dVlnVkN3dUdpOVpHTzVVTw$5yua+f8X+J+Oo4n9K0XsTxYoxJ6x4h6OMqHsBPRJdkQ";
const PHP_PLAINTEXT = "CorrectHorse!42";

describe("legacy PHP hash compatibility", () => {
  it("verifies a hash produced by PHP password_hash(PASSWORD_ARGON2ID)", async () => {
    // The migration carries legacy hashes across unchanged; if this ever
    // returns false, every admin needs a password reset at cutover.
    await expect(verifyPassword(PHP_ARGON2ID_HASH, PHP_PLAINTEXT)).resolves.toBe(true);
  });

  it("rejects a wrong password against the same legacy hash", async () => {
    await expect(verifyPassword(PHP_ARGON2ID_HASH, "wrong-password")).resolves.toBe(
      false,
    );
  });

  it("emits hashes in the same PHC encoding and parameters PHP uses", async () => {
    const produced = await hashPassword("some-new-password");
    const [, algorithm, version, params] = produced.split("$");
    const [, phpAlgorithm, phpVersion, phpParams] = PHP_ARGON2ID_HASH.split("$");

    // Matching parameters keep a staged cutover coherent: a password changed in
    // the new system produces a hash the legacy system would also accept.
    expect(algorithm).toBe(phpAlgorithm);
    expect(version).toBe(phpVersion);
    expect(params).toBe(phpParams);
  });
});

describe("password hashing", () => {
  it("round-trips a password", async () => {
    const hash = await hashPassword("s3cure-p@ssword");
    await expect(verifyPassword(hash, "s3cure-p@ssword")).resolves.toBe(true);
    await expect(verifyPassword(hash, "s3cure-p@sswore")).resolves.toBe(false);
  });

  it("salts, so identical passwords hash differently", async () => {
    const first = await hashPassword("same-password");
    const second = await hashPassword("same-password");
    expect(first).not.toBe(second);
    // Both still verify - the salt lives in the encoded string.
    await expect(verifyPassword(first, "same-password")).resolves.toBe(true);
    await expect(verifyPassword(second, "same-password")).resolves.toBe(true);
  });

  it("returns false rather than throwing on a malformed stored hash", async () => {
    // A corrupt row must fail the login, not surface a 500 that reveals the row
    // exists at all.
    await expect(verifyPassword("not-a-hash", "anything")).resolves.toBe(false);
    await expect(verifyPassword("", "anything")).resolves.toBe(false);
  });
});

describe("timing equalisation", () => {
  it("verifies against a dummy hash without throwing", async () => {
    // Called on the unknown-email path so its cost matches the wrong-password
    // path; the endpoint must not become a user-enumeration oracle.
    await expect(verifyAgainstDummy("whatever")).resolves.toBeUndefined();
  });

  it("costs roughly the same as a real verification", async () => {
    const hash = await hashPassword("real-password");

    const realStart = performance.now();
    await verifyPassword(hash, "wrong-password");
    const realCost = performance.now() - realStart;

    const dummyStart = performance.now();
    await verifyAgainstDummy("wrong-password");
    const dummyCost = performance.now() - dummyStart;

    // A loose bound deliberately: the point is that the unknown-email path does
    // real Argon2 work rather than returning immediately, not that the two are
    // identical to the microsecond. A tight assertion would be flaky on shared
    // CI without testing anything stronger.
    expect(dummyCost).toBeGreaterThan(realCost * 0.2);
  });
});
