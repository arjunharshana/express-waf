import { Request, Response, NextFunction } from "express";
import { WafConfig } from "../types";
import { detectSQLi } from "../detectors/sqli";
import { detectXSS } from "../detectors/xss";
import { detectNoSQLi } from "../detectors/nosqli";
import { detectLFI } from "../detectors/lfi";

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

    // Check Query Params
    if (config.inspectionRules.checkQuery && req.query) {
      targets.push({
        type: "payload",
        location: "query",
        value: JSON.stringify(req.query),
      });
    }

    // Check Body
    if (config.inspectionRules.checkBody && req.body) {
      try {
        targets.push({
          type: "payload",
          location: "body",
          value: JSON.stringify(req.body),
        });
      } catch (e) {
        console.error("[WAF] Failed to stringify request body");
      }
    }

    if (config.inspectionRules.checkHeaders) {
      for (const header of SCANNED_HEADERS) {
        const value = req.headers[header];
        if (typeof value === "string")
          targets.push({ type: "header", location: `header.${header}`, value });
      }
    }

    // detection loop
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

        // Run NoSQLi Detector
        const nosqliResult = detectNoSQLi(value);
        if (!nosqliResult.clean) {
          return handleBlock(
            req,
            res,
            config,
            "NoSQLi",
            nosqliResult.rule,
            location,
            nosqliResult.matched,
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

      if (type !== "header") {
        const sqliResult = detectSQLi(value);
        if (!sqliResult.clean)
          return handleBlock(
            req,
            res,
            config,
            "SQLi",
            sqliResult.rule,
            location,
            sqliResult.matched,
          );

        const nosqliResult = detectNoSQLi(value);
        if (!nosqliResult.clean)
          return handleBlock(
            req,
            res,
            config,
            "NoSQLi",
            nosqliResult.rule,
            location,
            nosqliResult.matched,
          );

        // lfi inspection
        const lfiResult = detectLFI(value);
        if (!lfiResult.clean)
          return handleBlock(
            req,
            res,
            config,
            "LFI",
            lfiResult.rule,
            location,
            lfiResult.matched,
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
