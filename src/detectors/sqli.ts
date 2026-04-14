import type { Request, Response, NextFunction } from "express";

export type ScanResult =
  | { clean: true }
  | { clean: false; rule: string; matched: string };

const sqliRules: { name: string; pattern: RegExp }[] = [
  // tautology based sqli
  {
    name: "TAUTOLOGY_OR_AND",
    pattern: /\b(?:or|and)\b\s+['"]?[\w\s]+['"]?\s*=\s*['"]?[\w\s]+['"]?/,
  },

  // UNION-based SQLi
  {
    name: "UNION_SELECT",
    pattern: /\bunion\s+(?:all\s+)?select\b/,
  },

  // Destructive SQL commands
  {
    name: "DESTRUCTIVE_COMMANDS",
    pattern:
      /\b(?:drop\s+table|insert\s+into|delete\s+from|update\s+\S+\s+set|truncate\s+table)\b/,
  },

  // Comment-based evasion
  {
    name: "COMMENT_INJECTION",

    pattern: /(?:--|(?:^|[\s;'"])#)/,
  },

  // System functions and time-based SQLi
  {
    name: "SYSTEM_FUNCTIONS",
    pattern:
      /\b(?:sleep\s*\(|waitfor\s+delay|@@version|xp_cmdshell|benchmark\s*\(|pg_sleep\s*\()\b/,
  },

  // Stacked queries (multiple statements in one payload)
  {
    name: "STACKED_QUERIES",
    pattern:
      /;\s*\b(?:select|insert|update|delete|drop|exec|execute|truncate)\b/,
  },

  // EXEC/EXECUTE calls (SQL Server)
  {
    name: "EXEC_CALLS",
    pattern: /\b(?:exec|execute)\s+\w+/,
  },

  // File access functions
  {
    name: "FILE_ACCESS",
    pattern: /\b(?:load_file\s*\(|into\s+(?:out|dump)file\b)/,
  },

  {
    name: "SCHEMA_RECON",
    pattern: /\binformation_schema\b/,
  },

  // encoding primitives
  {
    name: "ENCODING_PRIMITIVES",
    pattern: /\b(?:char\s*\(|0x[0-9a-f]{2,})\b/,
  },
];

// function to fully decode URL-encoded payloads
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

function stripSqlComments(payload: string): string {
  // [\s\S]*? matches any character including newlines, non-greedy
  return payload.replace(/\/\*[\s\S]*?\*\//g, "");
}

export const detectSQLi = (payload: string): ScanResult => {
  if (!payload) return { clean: true };

  const decoded = fullyDecode(payload);
  const stripped = stripSqlComments(decoded);
  const normalized = stripped.toLowerCase();

  for (const rule of sqliRules) {
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

export function sqliMiddleware() {
  return (req: Request, res: Response, next: NextFunction): void => {
    const targets: { location: string; value: string }[] = [];

    for (const [key, value] of Object.entries(req.query)) {
      if (typeof value === "string") {
        targets.push({ location: `query.${key}`, value });
      }
    }

    // Collect flat string body fields
    if (req.body && typeof req.body === "object") {
      for (const [key, value] of Object.entries(req.body)) {
        if (typeof value === "string") {
          targets.push({ location: `body.${key}`, value });
        }
      }
    }

    for (const { location, value } of targets) {
      const result = detectSQLi(value);
      if (!result.clean) {
        console.warn(
          `[WAF] SQLi blocked | rule=${result.rule} | location=${location} | ` +
            `ip=${req.ip} | path=${req.path} | matched="${result.matched}"`,
        );
        res.status(400).json({ error: "Bad request" });
        return;
      }
    }

    next();
  };
}
