// src/detectors/lfi.ts

export type ScanResult =
  | { clean: true }
  | { clean: false; rule: string; matched: string };

const lfiRules: { name: string; pattern: RegExp }[] = [
  // directory traversal
  {
    name: "PATH_TRAVERSAL",
    pattern: /(?:\.\.[/\\])+/,
  },

  // sensitive files
  {
    name: "SENSITIVE_FILES",
    pattern:
      /(?:\/etc\/(?:passwd|shadow|issue|hostname|hosts|group)|[a-z]:\\(?:windows|winnt|boot\.ini))/i,
  },

  // dangerous wrappers
  {
    name: "MALICIOUS_WRAPPERS",
    pattern: /(?:php|file|zlib|data|expect|glob|phar):\/\//i,
  },

  // null byte injection
  {
    name: "NULL_BYTE",
    pattern: /\x00/,
  },
];

function fullyDecode(payload: string): string {
  let decoded = payload;
  let prev = "";
  while (prev !== decoded) {
    prev = decoded;
    try {
      decoded = decodeURIComponent(decoded);
    } catch {
      break;
    }
  }
  return decoded;
}

export const detectLFI = (payload: string): ScanResult => {
  if (!payload) return { clean: true };

  const normalized = fullyDecode(payload);

  for (const rule of lfiRules) {
    const match = normalized.match(rule.pattern);
    if (match) {
      return {
        clean: false,
        rule: rule.name,
        matched: match[0].substring(0, 120),
      };
    }
  }

  return { clean: true };
};
