export type ScanResult =
  | { clean: true }
  | { clean: false; rule: string; matched: string };

const nosqliRules: { name: string; pattern: RegExp }[] = [
  //mongodb operators that are commonly abused in NoSQLi attacks
  {
    name: "MONGO_OPERATORS",
    pattern:
      /\$(?:eq|ne|gt|gte|lt|lte|in|nin|or|and|not|nor|where|regex|expr|type|mod|all|size|exists|slice)\b/i,
  },

  //js execution patterns that are commonly used in NoSQLi attacks
  {
    name: "JS_EXECUTION",
    pattern: /\b(?:sleep|while\s*\(\s*1\s*\)|tojson|return\s+db\.|this\.)/i,
  },

  {
    name: "SYSTEM_COLLECTIONS",
    pattern:
      /\b(?:system\.users|system\.indexes|system\.namespaces|system\.profile)\b/i,
  },
];

export const detectNoSQLi = (payload: string): ScanResult => {
  if (!payload) return { clean: true };

  const normalized = payload.toLowerCase();

  for (const rule of nosqliRules) {
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
