import { Request, Response, NextFunction } from "express";

export interface IpManagerOptions {
  whitelist?: string[];
  blacklist?: string[];

  blockMessage?: string;
}

// convert wildcard ips to regex
const compileIpRules = (ips: string[]): RegExp[] => {
  return ips.map((ip) => {
    const regexString = ip.replace(/\./g, "\\.").replace(/\*/g, ".*");
    return new RegExp(`^${regexString}$`);
  });
};

export const ipManager = (options: IpManagerOptions = {}) => {
  const config: IpManagerOptions = {
    whitelist: [],
    blacklist: [],
    blockMessage: "Access denied: IP address is blacklisted.",
    ...options,
  };

  const whitelistRules = compileIpRules(config.whitelist!);
  const blacklistRules = compileIpRules(config.blacklist!);

  return (req: Request, res: Response, next: NextFunction): void => {
    const ip = req.ip || req.socket.remoteAddress || "unknown";

    for (const rule of whitelistRules) {
      if (rule.test(ip)) {
        (req as any).isWhitelisted = true;
        return next();
      }
    }

    // blacklist
    for (const rule of blacklistRules) {
      if (rule.test(ip)) {
        console.warn(`[WAF] Connection dropped | Blacklisted IP=${ip}`);
        res.status(403).json({
          success: false,
          error: config.blockMessage,
        });
        return;
      }
    }

    next();
  };
};
