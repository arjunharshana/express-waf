import { detectXSS } from "../src/detectors/xss";

describe("XSS Detector", () => {
  describe("Safe Payloads", () => {
    it("should allow normal text", () => {
      const result = detectXSS("Hello world, this is a comment.");
      expect(result.clean).toBe(true);
    });

    it("should allow safe HTML formatting", () => {
      const result = detectXSS("This is <b>bold</b> and <i>italic</i>.");
      expect(result.clean).toBe(true);
    });
  });

  describe("Malicious Payloads", () => {
    it("should block basic script tags", () => {
      const result = detectXSS("<script>alert(1)</script>");
      expect(result.clean).toBe(false);
      if (!result.clean) expect(result.rule).toBe("DANGEROUS_TAGS");
    });

    it("should block inline event handlers", () => {
      const result = detectXSS("<b onmouseover=alert(1)>Hover me</b>");
      expect(result.clean).toBe(false);
      if (!result.clean) expect(result.rule).toBe("EVENT_HANDLERS");
    });

    it("should block javascript: URIs", () => {
      const result = detectXSS("<a href='javascript:alert(1)'>Click</a>");
      expect(result.clean).toBe(false);
      if (!result.clean) expect(result.rule).toBe("MALICIOUS_URIS");
    });
  });

  describe("Evasion and Obfuscation", () => {
    it("should catch Unicode Fullwidth characters (Bypass Attempt)", () => {
      const result = detectXSS("＜script＞alert(1)＜/script＞");
      expect(result.clean).toBe(false);
      if (!result.clean) expect(result.rule).toBe("DANGEROUS_TAGS");
    });

    it("should catch heavily HTML-Entity Encoded payloads", () => {
      // &lt;script&gt;
      const result = detectXSS("&#x3C;script&#x3E;alert(1)");
      expect(result.clean).toBe(false);
      if (!result.clean) expect(result.rule).toBe("DANGEROUS_TAGS");
    });

    it("should defeat whitespace attribute splitting", () => {
      const payload = "<img\nsrc=x\n\ronerror\n=\nalert(1)>";
      const result = detectXSS(payload);
      expect(result.clean).toBe(false);
    });
  });
});
