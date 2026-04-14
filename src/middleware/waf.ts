import { Request, Response, NextFunction } from "express";
import { WafConfig } from "../types";
import { detectSQLi } from "../detectors/sqli";
import { detectXSS } from "../detectors/xss";

const defaultConfig: WafConfig = {
  enabled: true,
  blockMalicious: true,
  blockMessage: "Forbidden: Malicious payload detected by WAF",
  statusCode: 403,
  inspectionRules: {
    checkBody: true,
    checkQuery: true,
    checkHeaders: true,
  },
};

const SCANNED_HEADERS = ["referer", "user-agent", "x-forwarded-for"];

export const createWaf = (userConfig: Partial<WafConfig> = {}) => {
  const config: WafConfig = {
    ...defaultConfig,
    ...userConfig,
    inspectionRules: {
      ...defaultConfig.inspectionRules,
      ...(userConfig.inspectionRules || {}),
    },
  };

  return (req: Request, res: Response, next: NextFunction): void => {
    if (!config.enabled) return next();

    const targets: {
      type: "payload" | "header";
      location: string;
      value: string;
    }[] = [];

    if (config.inspectionRules.checkQuery && req.query) {
      for (const [key, value] of Object.entries(req.query)) {
        if (typeof value === "string")
          targets.push({ type: "payload", location: `query.${key}`, value });
      }
    }

    if (
      config.inspectionRules.checkBody &&
      req.body &&
      typeof req.body === "object"
    ) {
      for (const [key, value] of Object.entries(req.body)) {
        if (typeof value === "string")
          targets.push({ type: "payload", location: `body.${key}`, value });
      }
    }

    if (config.inspectionRules.checkHeaders) {
      for (const header of SCANNED_HEADERS) {
        const value = req.headers[header];
        if (typeof value === "string")
          targets.push({ type: "header", location: `header.${header}`, value });
      }
    }

    for (const { type, location, value } of targets) {
      if (type !== "header") {
        const sqliResult = detectSQLi(value);
        if (!sqliResult.clean) {
          return handleBlock(
            req,
            res,
            config,
            "SQLi",
            sqliResult.rule,
            location,
            sqliResult.matched,
          );
        }
      }

      // XSS Inspection
      const xssResult = detectXSS(value);
      if (!xssResult.clean) {
        return handleBlock(
          req,
          res,
          config,
          "XSS",
          xssResult.rule,
          location,
          xssResult.matched,
        );
      }
    }

    next();
  };
};

function handleBlock(
  req: Request,
  res: Response,
  config: WafConfig,
  attackType: string,
  rule: string,
  location: string,
  matched: string,
): void {
  console.warn(
    `[WAF] ${attackType} blocked | rule=${rule} | location=${location} | ip=${req.ip} | path=${req.path} | matched="${matched}"`,
  );

  if (config.blockMalicious) {
    res.status(config.statusCode).json({
      success: false,
      error: config.blockMessage,
    });
  }
}
