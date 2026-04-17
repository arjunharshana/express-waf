import { EventEmitter } from "events";
import { LogPayload } from "./logger";

export interface RateLimitPayload {
  ip: string;
  path: string;
  method: string;
  limit: number;
  requestCount: number;
}

export interface BlacklistPayload {
  ip: string;
  path: string;
  method: string;
  reason: string;
}

interface WafEvents {
  attack: (data: LogPayload) => void;
  rateLimit: (data: RateLimitPayload) => void;
  blacklistedIp: (data: BlacklistPayload) => void;
  error: (err: Error) => void;
}

class WafEventEmitter extends EventEmitter {
  constructor() {
    super();
    this.setMaxListeners(25);

    this.on("error", (err: Error) => {
      console.error(`[WAF EventEmitter] Unhandled error event: ${err.message}`);
    });
  }
  public on<K extends keyof WafEvents>(event: K, listener: WafEvents[K]): this {
    return super.on(event, listener);
  }

  public once<K extends keyof WafEvents>(
    event: K,
    listener: WafEvents[K],
  ): this {
    return super.once(event, listener);
  }

  public off<K extends keyof WafEvents>(
    event: K,
    listener: WafEvents[K],
  ): this {
    return super.off(event, listener);
  }

  public prependListener<K extends keyof WafEvents>(
    event: K,
    listener: WafEvents[K],
  ): this {
    return super.prependListener(event, listener);
  }

  public prependOnceListener<K extends keyof WafEvents>(
    event: K,
    listener: WafEvents[K],
  ): this {
    return super.prependOnceListener(event, listener);
  }

  public emit<K extends keyof WafEvents>(
    event: K,
    ...args: Parameters<WafEvents[K]>
  ): boolean {
    return super.emit(event, ...args);
  }
}

export const wafEvents = new WafEventEmitter();
