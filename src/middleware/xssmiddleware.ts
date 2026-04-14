import { Request, Response, NextFunction } from "express";
import { detectXSS } from "../detectors/xss";

export function xssMiddleware() {
  const SCANNED_HEADERS = ["referer", "user-agent", "x-forwarded-for"];

  return (req: Request, res: Response, next: NextFunction): void => {
    const targets: { location: string; value: string }[] = [];

    // Query parameters
    for (const [key, value] of Object.entries(req.query)) {
      if (typeof value === "string") {
        targets.push({ location: `query.${key}`, value });
      }
    }

    // Body fields
    if (req.body && typeof req.body === "object") {
      for (const [key, value] of Object.entries(req.body)) {
        if (typeof value === "string") {
          targets.push({ location: `body.${key}`, value });
        }
      }
    }

    // Selected headers
    for (const header of SCANNED_HEADERS) {
      const value = req.headers[header];
      if (typeof value === "string") {
        targets.push({ location: `header.${header}`, value });
      }
    }

    for (const { location, value } of targets) {
      const result = detectXSS(value);
      if (!result.clean) {
        console.warn(
          `[WAF] XSS blocked | rule=${result.rule} | location=${location} | ` +
            `ip=${req.ip} | path=${req.path} | matched="${result.matched}"`,
        );
        res.status(400).json({ error: "Bad request" });
        return;
      }
    }

    next();
  };
}
