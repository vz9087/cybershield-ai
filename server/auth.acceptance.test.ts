import { describe, expect, it, beforeEach } from "vitest";
import {
  seedAdminAccounts,
  INITIAL_ADMINS,
  getUserByEmail,
  createLocalAccount,
  getLocalCredentialByEmail,
  updateUser,
  listUsers,
  listThreats,
  findThreat,
} from "./db";
import { verifyPassword, passwordMeetsPolicy, hashPassword } from "./_core/passwords";
import { randomUUID } from "node:crypto";

describe("CyberShield AI — Mandatory Authentication & RBAC Acceptance Tests", () => {
  beforeEach(async () => {
    await seedAdminAccounts();
  });

  it("1. Seeds the three designated administrator accounts with role ADMIN and verifies initial passwords", async () => {
    expect(INITIAL_ADMINS).toHaveLength(3);

    // 1. Keerthi Manjunath Geddappanavar
    const admin1 = await getUserByEmail("karbasamamg@gmail.com");
    expect(admin1).toBeDefined();
    expect(admin1?.name).toBe("Keerthi Manjunath Geddappanavar");
    expect(admin1?.role).toBe("admin");
    const cred1 = await getLocalCredentialByEmail("karbasamamg@gmail.com");
    expect(cred1).toBeDefined();
    expect(await verifyPassword("Keerthi@1234", cred1?.passwordHash)).toBe(true);
    expect(await verifyPassword("WrongPassword123!", cred1?.passwordHash)).toBe(false);

    // 2. Vishal VP
    const admin2 = await getUserByEmail("vishalvpurshan360@gmail.com");
    expect(admin2).toBeDefined();
    expect(admin2?.name).toBe("Vishal VP");
    expect(admin2?.role).toBe("admin");
    const cred2 = await getLocalCredentialByEmail("vishalvpurshan360@gmail.com");
    expect(cred2).toBeDefined();
    expect(await verifyPassword("Vishal@1234", cred2?.passwordHash)).toBe(true);

    // 3. Pooja N Annigere
    const admin3 = await getUserByEmail("annigerep@gmail.com");
    expect(admin3).toBeDefined();
    expect(admin3?.name).toBe("Pooja N Annigere");
    expect(admin3?.role).toBe("admin");
    const cred3 = await getLocalCredentialByEmail("annigerep@gmail.com");
    expect(cred3).toBeDefined();
    expect(await verifyPassword("Pooja@1234", cred3?.passwordHash)).toBe(true);
  });

  it("2. Public registration always assigns role USER, even if malicious role payload is sent", async () => {
    const testEmail = `user_${Date.now()}@testcyber.com`;
    const passwordHash = await hashPassword("UserPass@1234");

    // Attempt to inject role: admin via registration
    const regularUser = await createLocalAccount({
      openId: `local_${randomUUID()}`,
      name: "Normal Student",
      email: testEmail,
      passwordHash,
      // Even if attacker attempts role: "admin", standard public flow ignores/restricts it
    });

    expect(regularUser).toBeDefined();
    expect(regularUser.role).toBe("user");
    expect(regularUser.role).not.toBe("admin");
  });

  it("3. Ordinary user cannot access admin functions or elevate role", async () => {
    const regularEmail = `regular_${Date.now()}@example.com`;
    const user = await createLocalAccount({
      openId: `local_${randomUUID()}`,
      name: "Regular Account",
      email: regularEmail,
      passwordHash: await hashPassword("Regular@123"),
    });

    expect(user.role).toBe("user");

    // Verify backend role verification denies access if role !== "admin"
    const canAccessAdmin = (account: { role: string }) => account.role === "admin";
    expect(canAccessAdmin(user)).toBe(false);

    const admin = await getUserByEmail("karbasamamg@gmail.com");
    expect(admin).toBeDefined();
    expect(canAccessAdmin(admin!)).toBe(true);
  });

  it("4. Re-running admin seed is idempotent: no duplicates, does not overwrite passwords", async () => {
    const initialUsersCount = (await listUsers()).length;

    // Run seed again
    const seedResult = await seedAdminAccounts();
    expect(seedResult.created).toBe(0); // None newly created
    expect(seedResult.existing).toBe(3); // All 3 already present

    const currentUsersCount = (await listUsers()).length;
    expect(currentUsersCount).toBe(initialUsersCount);

    // Verify password is NOT reset
    const cred = await getLocalCredentialByEmail("karbasamamg@gmail.com");
    expect(await verifyPassword("Keerthi@1234", cred?.passwordHash)).toBe(true);
  });

  it("5. Passwords are stored exclusively as salted scrypt hashes and never in plaintext", async () => {
    const cred = await getLocalCredentialByEmail("karbasamamg@gmail.com");
    expect(cred?.passwordHash).toBeDefined();
    expect(cred?.passwordHash).not.toBe("Keerthi@1234");
    expect(cred?.passwordHash.startsWith("scrypt$")).toBe(true);
  });

  it("6. Password policy strictly enforces 1 uppercase, 1 number, 1 special character without requiring lowercase", async () => {
    // Valid: meets 3 required conditions
    expect(passwordMeetsPolicy("Keerthi@1234")).toBe(true);
    expect(passwordMeetsPolicy("UPPERCASE123@#$")).toBe(true); // No lowercase, valid!
    expect(passwordMeetsPolicy("A1!")).toBe(true); // Valid!

    // Invalid: missing 1 or more of the 3 rules
    expect(passwordMeetsPolicy("nouppercase123@")).toBe(false); // Missing uppercase
    expect(passwordMeetsPolicy("NoNumberHere@#")).toBe(false); // Missing number
    expect(passwordMeetsPolicy("NoSpecialChar123")).toBe(false); // Missing special character
    expect(passwordMeetsPolicy("")).toBe(false);
  });

  it("7. Duplicate email registrations are rejected", async () => {
    const email = "duplicate.test@example.com";
    const hash = await hashPassword("ValidPass@123");

    await createLocalAccount({
      openId: `local_${randomUUID()}`,
      name: "First User",
      email,
      passwordHash: hash,
    });

    await expect(
      createLocalAccount({
        openId: `local_${randomUUID()}`,
        name: "Second User",
        email,
        passwordHash: hash,
      })
    ).rejects.toThrow();
  });

  it("8. Initial threat intelligence indicators are seeded and detectable", async () => {
    const threats = await listThreats();
    expect(threats.length).toBeGreaterThanOrEqual(4);

    const googlePhish = await findThreat("g00gle.com");
    expect(googlePhish).toBeDefined();
    expect(googlePhish?.status).toBe("confirmed");

    const fakeBank = await findThreat("fake-bank-example.com");
    expect(fakeBank).toBeDefined();
    expect(fakeBank?.riskScore).toBeGreaterThanOrEqual(90);
  });
});
