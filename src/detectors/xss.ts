// src/detectors/xss.ts
import type { Request, Response, NextFunction } from "express";

export type ScanResult =
  | { clean: true }
  | { clean: false; rule: string; matched: string };

const xssRules: { name: string; pattern: RegExp }[] = [
  // html tags commonly used in XSS attacks.
  {
    name: "DANGEROUS_TAGS",
    pattern:
      /<(?:\/)?(?:script|iframe|object|embed|applet|meta|svg|math|base|form|link|style|img|input|body|video|audio|source|track|details|marquee|frameset|frame|bgsound|isindex|xss)(?:[\s/>\n\r\t]|$)/,
  },

  // inline event handler

  {
    name: "EVENT_HANDLERS",
    pattern: /\bon\w+\s*=/,
  },

  //javascript uris and data uris
  {
    name: "MALICIOUS_URIS",
    pattern:
      /(?:j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t|v\s*b\s*s\s*c\s*r\s*i\s*p\s*t|d\s*a\s*t\s*a)\s*:/,
  },

  // CSS expressions and JavaScript URLs in style attributes
  {
    name: "CSS_EXPRESSION",
    pattern: /\bexpression\s*\(|url\s*\(\s*(?:javascript|data)\s*:/,
  },

  // Template injection patterns (e.g. ${…}, #{…}, {{…}}, <% %>, <?php)
  {
    name: "TEMPLATE_INJECTION",
    pattern: /(?:\$\{|#\{|\{\{[\s\S]*?\}\}|\{%|<%|@\{|<\?(?:php)?)/,
  },

  // Dangerous attributes that can lead to XSS when used in tags
  {
    name: "DANGEROUS_ATTRIBUTES",
    pattern:
      /\b(?:srcdoc|formaction|xlink:href|xmlns|dangerouslysetinnerhtml)\s*=/,
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

function decodeHtmlEntities(payload: string): string {
  const namedEntities: Record<string, string> = {
    "&lt;": "<",
    "&gt;": ">",
    "&quot;": '"',
    "&apos;": "'",
    "&amp;": "&",
    "&nbsp;": " ",
    "&sol;": "/",
    "&colon;": ":",
    "&lpar;": "(",
    "&rpar;": ")",
    "&equals;": "=",
  };

  function decodeOnce(s: string): string {
    // decode hex
    s = s.replace(/&#x([0-9a-f]+);?/gi, (_, hex) =>
      String.fromCharCode(parseInt(hex, 16)),
    );

    // decode decimal
    s = s.replace(/&#(\d+);?/g, (_, dec) =>
      String.fromCharCode(parseInt(dec, 10)),
    );

    s = s.replace(
      /&(?:lt|gt|quot|apos|amp|nbsp|sol|colon|lpar|rpar|equals);/gi,
      (match) => namedEntities[match.toLowerCase()] ?? match,
    );
    return s;
  }

  let decoded = payload;
  let prev = "";
  while (prev !== decoded) {
    prev = decoded;
    decoded = decodeOnce(decoded);
  }
  return decoded;
}

// Normalize fullwidth Unicode characters to their ASCII equivalents
function normalizeUnicode(payload: string): string {
  return payload.replace(/[\uFF01-\uFF5E]/g, (ch) =>
    String.fromCharCode(ch.charCodeAt(0) - 0xfee0),
  );
}

function normalizePayload(payload: string): string {
  let s = payload;

  s = fullyDecode(s);
  s = decodeHtmlEntities(s);
  s = normalizeUnicode(s);

  s = s.replace(/\0/g, "");

  s = s.replace(/[\t\n\r\f\v]+/g, " ");

  s = s.toLowerCase();

  return s;
}

export const detectXSS = (payload: string): ScanResult => {
  if (!payload) return { clean: true };

  const normalized = normalizePayload(payload);

  for (const rule of xssRules) {
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
