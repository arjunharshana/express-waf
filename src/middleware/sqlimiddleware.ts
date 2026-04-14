import { Request, Response, NextFunction } from "express";
import { detectSQLi } from "../detectors/sqli";

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
