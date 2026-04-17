import { detectLFI } from "../src/detectors/lfi";

describe("Local File Inclusion (LFI) Detector", () => {
  describe("Safe Payloads", () => {
    it("should allow normal filenames", () => {
      const result = detectLFI("report_2026.pdf");
      expect(result.clean).toBe(true);
    });

    it("should allow normal internal routing paths", () => {
      const result = detectLFI("/api/users/profile/image");
      expect(result.clean).toBe(true);
    });
  });

  describe("Malicious Payloads", () => {
    it("should block standard Directory Traversal", () => {
      const result = detectLFI("../../../../etc/passwd");
      expect(result.clean).toBe(false);
      if (!result.clean) expect(result.rule).toBe("PATH_TRAVERSAL");
    });

    it("should block direct requests to Sensitive Files", () => {
      const result = detectLFI("/etc/shadow");
      expect(result.clean).toBe(false);
      if (!result.clean) expect(result.rule).toBe("SENSITIVE_FILES");
    });

    it("should block PHP Wrappers", () => {
      const result = detectLFI(
        "php://filter/convert.base64-encode/resource=index.php",
      );
      expect(result.clean).toBe(false);
      if (!result.clean) expect(result.rule).toBe("MALICIOUS_WRAPPERS");
    });
  });

  describe("Evasion and Obfuscation", () => {
    it("should catch heavily URL encoded traversal", () => {
      // %2e%2e%2f is ../
      const result = detectLFI("%2e%2e%2f%2e%2e%2fetc%2fpasswd");
      expect(result.clean).toBe(false);
    });

    it("should catch Null Byte injections", () => {
      const result = detectLFI("image.jpg\x00.php");
      expect(result.clean).toBe(false);
      if (!result.clean) expect(result.rule).toBe("NULL_BYTE");
    });
  });
});
