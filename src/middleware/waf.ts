import { Request, Response, NextFunction } from "express";
import { WafConfig } from "../types";

// define default config
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

// function for creating WAF middleware
export function createWaf(userConfig: Partial<WafConfig> = {}) {
  const config: WafConfig = {
    ...defaultConfig,
    ...userConfig,
    inspectionRules: {
      ...defaultConfig.inspectionRules,
      ...(userConfig?.inspectionRules || {}),
    },
  };

  return (req: Request, res: Response, next: NextFunction): void => {
    if (!config.enabled) {
      return next();
    }

    // gather payloads based on inspection rules
    const payloadsToInspect: string[] = [];

    if (config.inspectionRules.checkQuery && req.query) {
      payloadsToInspect.push(JSON.stringify(req.query));
    }
    if (config.inspectionRules.checkBody && req.body) {
      payloadsToInspect.push(JSON.stringify(req.body));
    }
    if (config.inspectionRules.checkHeaders && req.headers) {
      payloadsToInspect.push(JSON.stringify(req.headers));
    }

    const combinedPayload = payloadsToInspect.join(" ").toLowerCase();

    // detection phase
    let isMalicious = false;
    let attackType = "None";

    // regex engine will go here

    // if detected as malicious, log and block if configured
    if (isMalicious) {
      console.warn(
        `[WAF ALERT] ${attackType} attempt blocked from IP: ${req.ip}`,
      );

      if (config.blockMalicious) {
        res.status(config.statusCode).json({
          success: false,
          error: config.blockMessage,
        });
        return; // stop further processing
      }
    }
    next();
  };
}
