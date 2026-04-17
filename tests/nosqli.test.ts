import { detectNoSQLi } from "../src/detectors/nosqli";

describe("NoSQL Injection Detector", () => {
  describe("Safe Payloads", () => {
    it("should allow normal JSON payloads", () => {
      const payload = JSON.stringify({
        username: "admin",
        password: "password123",
      });
      const result = detectNoSQLi(payload);
      expect(result.clean).toBe(true);
    });

    it("should allow normal text that contains operator letters", () => {
      const result = detectNoSQLi("getting a new user");
      expect(result.clean).toBe(true);
    });
  });

  describe("Malicious Payloads", () => {
    it("should block MongoDB Query Operators", () => {
      const payload = JSON.stringify({ username: { $ne: null } });
      const result = detectNoSQLi(payload);
      expect(result.clean).toBe(false);
      if (!result.clean) expect(result.rule).toBe("MONGO_OPERATORS");
    });

    it("should block JavaScript execution bypasses ($where)", () => {
      const payload = JSON.stringify({
        custom_query: "function() { sleep(5000); }",
      });
      const result = detectNoSQLi(payload);
      expect(result.clean).toBe(false);
      if (!result.clean) expect(result.rule).toBe("JS_EXECUTION"); // It catches 'sleep' or 'where'
    });

    it("should block System Collection access", () => {
      const result = detectNoSQLi("db.system.users.find()");
      expect(result.clean).toBe(false);
      if (!result.clean) expect(result.rule).toBe("SYSTEM_COLLECTIONS");
    });
  });
});
