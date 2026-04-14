import { Request, Response, NextFunction } from "express";
import { WafConfig } from "../types";
import { detectSQLi } from "../detectors/sqli";

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
    if (!config.enabled) {
      return next();
    }

    const targets: { location: string; value: string }[] = [];

    if (config.inspectionRules.checkQuery && req.query) {
      for (const [key, value] of Object.entries(req.query)) {
        if (typeof value === "string")
          targets.push({ location: `query.${key}`, value });
      }
    }

    if (
      config.inspectionRules.checkBody &&
      req.body &&
      typeof req.body === "object"
    ) {
      for (const [key, value] of Object.entries(req.body)) {
        if (typeof value === "string")
          targets.push({ location: `body.${key}`, value });
      }
    }

    for (const { location, value } of targets) {
      // Run the SQLi Detector
      const sqliResult = detectSQLi(value);

      if (!sqliResult.clean) {
        // If it fails, we trigger the block action
        console.warn(
          `[WAF ALERT] SQLi blocked | rule=${sqliResult.rule} | location=${location} | ip=${req.ip} | matched="${sqliResult.matched}"`,
        );

        if (config.blockMalicious) {
          res.status(config.statusCode).json({
            success: false,
            error: config.blockMessage,
          });
          return;
        }
      }

      // xss and noqli here
    }

    next();
  };
};
