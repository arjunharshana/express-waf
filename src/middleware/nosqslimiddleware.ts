import { Request, Response, NextFunction } from "express";
import { detectNoSQLi } from "../detectors/nosqli";

export const nosqliMiddleware = () => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const targets: { location: string; value: string }[] = [];

    if (req.query && Object.keys(req.query).length > 0) {
      targets.push({ location: "query", value: JSON.stringify(req.query) });
    }

    if (
      req.body &&
      typeof req.body === "object" &&
      Object.keys(req.body).length > 0
    ) {
      try {
        targets.push({ location: "body", value: JSON.stringify(req.body) });
      } catch (e) {
        console.error(
          "[WAF] Failed to stringify request body for NoSQLi check",
        );
      }
    }

    for (const { location, value } of targets) {
      const result = detectNoSQLi(value);

      if (!result.clean) {
        console.warn(
          `[WAF] NoSQLi blocked | rule=${result.rule} | location=${location} | ` +
            `ip=${req.ip} | path=${req.path} | matched="${result.matched}"`,
        );

        res.status(403).json({
          success: false,
          error: "Forbidden: Malicious payload",
        });
        return;
      }
    }

    next();
  };
};
