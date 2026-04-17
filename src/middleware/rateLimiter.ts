import { Request, Response, NextFunction } from "express";
import { wafEvents } from "../telemetry/eventEmitter";

export interface RateLimitOptions {
  // time window
  windowMs: number;

  maxRequests: number;
  blockDurationMs?: number;
  message?: string;
}

interface ClientRecord {
  count: number;
  resetTime: number;
  blockUntil: number;
}

// tracking IPs using in-memory storage
const store = new Map<string, ClientRecord>();

// garbage collector
setInterval(
  () => {
    const now = Date.now();
    for (const [ip, record] of store.entries()) {
      if (now > record.resetTime && now > record.blockUntil) {
        store.delete(ip);
      }
    }
  },
  5 * 60 * 1000,
).unref();

export const rateLimiter = (options: Partial<RateLimitOptions> = {}) => {
  // default : 100 per minute
  const config: RateLimitOptions = {
    windowMs: 60 * 1000,
    maxRequests: 100,
    blockDurationMs: 0,
    message: "Too many requests, please try again later.",
    ...options,
  };

  return (req: Request, res: Response, next: NextFunction): void => {
    const ip = req.ip || req.socket.remoteAddress || "unknown";
    const now = Date.now();

    let record = store.get(ip);

    if (record && record.blockUntil > now) {
      res.status(429).json({ success: false, error: config.message });
      return;
    }

    if (!record || now > record.resetTime) {
      record = { count: 0, resetTime: now + config.windowMs, blockUntil: 0 };
      store.set(ip, record);
    }

    record.count += 1;

    if (record.count > config.maxRequests) {
      if (config.blockDurationMs && config.blockDurationMs > 0) {
        record.blockUntil = now + config.blockDurationMs;
      }

      wafEvents.emit("rateLimit", {
        ip,
        path: req.path,
        method: req.method,
        limit: config.maxRequests,
        requestCount: record.count,
      });
      console.warn(`[WAF] Rate limit exceeded | ip=${ip} | path=${req.path}`);
      res.status(429).json({ success: false, error: config.message });
      return;
    }

    next();
  };
};
