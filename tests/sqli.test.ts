import { detectSQLi } from "../src/detectors/sqli";

describe("SQL Injection Detector", () => {
  // test the safe inputs
  describe("Safe Payloads", () => {
    it("should allow normal names and text", () => {
      const result = detectSQLi("John Doe");
      expect(result.clean).toBe(true);
    });

    it("should allow normal punctuation", () => {
      const result = detectSQLi("O'Reilly, what's up?");
      expect(result.clean).toBe(true);
    });

    it("should handle empty payloads gracefully", () => {
      const result = detectSQLi("");
      expect(result.clean).toBe(true);
    });
  });

  // test the malicious inputs
  describe("Malicious Payloads", () => {
    it("should block Tautologies (Logic Bypasses)", () => {
      const result = detectSQLi("' OR 1=1 --");
      expect(result.clean).toBe(false);
      if (!result.clean) {
        expect(result.rule).toBe("TAUTOLOGY_OR_AND");
      }
    });

    it("should block UNION SELECT attacks", () => {
      const result = detectSQLi("admin' UNION SELECT password FROM users --");
      expect(result.clean).toBe(false);
      if (!result.clean) {
        expect(result.rule).toBe("UNION_SELECT");
      }
    });

    it("should block Destructive Commands", () => {
      const result = detectSQLi("'; DROP TABLE users; --");
      expect(result.clean).toBe(false);
      if (!result.clean) {
        expect(result.rule).toBe("DESTRUCTIVE_COMMANDS");
      }
    });

    it("should block Stacked Queries explicitly", () => {
      const result = detectSQLi("admin'; SELECT * FROM passwords");
      expect(result.clean).toBe(false);
      if (!result.clean) {
        expect(result.rule).toBe("STACKED_QUERIES");
      }
    });
  });

  // test evasion techniques
  describe("Evasion and Obfuscation", () => {
    it("should catch URL Encoded payloads (Double Encoding)", () => {
      const payload = "%252527%2520OR%25201%3D1";
      const result = detectSQLi(payload);

      expect(result.clean).toBe(false);
      if (!result.clean) {
        expect(result.rule).toBe("TAUTOLOGY_OR_AND");
      }
    });

    it("should catch Inline Comment Evasion", () => {
      const result = detectSQLi("UN/**/ION SEL/**/ECT * FROM users");

      expect(result.clean).toBe(false);
      if (!result.clean) {
        expect(result.rule).toBe("UNION_SELECT");
      }
    });
  });
});
