import { describe, expect, it } from "vitest";
import { hashPassword, passwordMeetsPolicy, verifyPassword } from "./passwords";

describe("local password helpers", () => {
  it("stores only distinct salted scrypt hashes and verifies the correct password", async () => {
    const first = await hashPassword("CorrectHorse9!Battery");
    const second = await hashPassword("CorrectHorse9!Battery");
    expect(first).not.toBe("CorrectHorse9!Battery");
    expect(first).not.toBe(second);
    expect(first.startsWith("scrypt$")).toBe(true);
    await expect(verifyPassword("CorrectHorse9!Battery", first)).resolves.toBe(true);
    await expect(verifyPassword("WrongPassword9!", first)).resolves.toBe(false);
    await expect(verifyPassword("CorrectHorse9!Battery", undefined)).resolves.toBe(false);
  });

  it("enforces exact password policy: uppercase, number, and special character", () => {
    // Valid cases
    expect(passwordMeetsPolicy("Keerthi@1234")).toBe(true);
    expect(passwordMeetsPolicy("Vishal@1234")).toBe(true);
    expect(passwordMeetsPolicy("Pooja@1234")).toBe(true);
    expect(passwordMeetsPolicy("ALLUPPER123!")).toBe(true); // Lowercase is not mandatory
    expect(passwordMeetsPolicy("A1!")).toBe(true); // Meets uppercase, number, special character

    // Invalid cases: missing any of the 3 required rules
    expect(passwordMeetsPolicy("password")).toBe(false); // No upper, number, special
    expect(passwordMeetsPolicy("alllowercase123!")).toBe(false); // No uppercase
    expect(passwordMeetsPolicy("ALLUPPERCASE!")).toBe(false); // No number
    expect(passwordMeetsPolicy("Uppercase12345")).toBe(false); // No special character
    expect(passwordMeetsPolicy("")).toBe(false); // Empty
  });
});
