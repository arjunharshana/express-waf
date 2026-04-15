import { Request, Response, NextFunction } from "express";
import { detectLFI } from "../detectors/lfi";

export const lfiMiddleware = () => {
  return (req: Request, res: Response, next: NextFunction): void => {
    const targets: { location: string; value: string }[] = [];

    // Check Query Params
    if (req.query) {
      for (const [key, value] of Object.entries(req.query)) {
        if (typeof value === "string")
          targets.push({ location: `query.${key}`, value });
      }
    }

    // Check Body ({"template": "../../admin.ejs"})
    if (req.body && typeof req.body === "object") {
      for (const [key, value] of Object.entries(req.body)) {
        if (typeof value === "string")
          targets.push({ location: `body.${key}`, value });
      }
    }

    // Check the raw URL path (Catches /api/download/..%2f..%2fetc%2fpasswd)
    targets.push({ location: "url", value: req.url });

    for (const { location, value } of targets) {
      const result = detectLFI(value);

      if (!result.clean) {
        console.warn(
          `[WAF] LFI blocked | rule=${result.rule} | location=${location} | ` +
            `ip=${req.ip} | path=${req.path} | matched="${result.matched}"`,
        );

        res
          .status(403)
          .json({ success: false, error: "Forbidden: Malicious payload" });
        return;
      }
    }

    next();
  };
};
