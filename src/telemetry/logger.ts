import fs from "fs";
import path from "path";

export interface LogPayload {
  attackType?: string;
  rule?: string;
  location?: string;
  ip?: string;
  path?: string;
  matched?: string;
  message?: string;
  statusCode?: number;
  method?: string;
}

function sanitizeField(value: string): string {
  return value.replace(/[\r\n]+/g, " ").trim();
}

function sanitizePayload(payload: LogPayload): LogPayload {
  const sanitized: LogPayload = {};
  for (const [key, value] of Object.entries(payload) as [
    keyof LogPayload,
    unknown,
  ][]) {
    if (typeof value === "string") {
      (sanitized as Record<string, unknown>)[key] = sanitizeField(value);
    } else if (value !== undefined) {
      (sanitized as Record<string, unknown>)[key] = value;
    }
  }
  return sanitized;
}

class WafLogger {
  private logStream: fs.WriteStream | null = null;
  private readonly logFilePath: string;

  constructor() {
    const logDir = path.join(process.cwd(), "logs");

    fs.mkdirSync(logDir, { recursive: true });

    this.logFilePath = path.join(logDir, "waf-security.log");
    this.logStream = fs.createWriteStream(this.logFilePath, { flags: "a" });

    this.logStream.on("error", (err) => {
      console.error(
        `[WAF LOGGER] Write stream error — logging to disk unavailable: ${err.message}`,
      );
      this.logStream = null;
    });

    const closeStream = () => {
      if (this.logStream) {
        this.logStream.end();
        this.logStream = null;
      }
    };
    process.once("exit", closeStream);
    process.once("SIGINT", () => {
      closeStream();
      process.exit(130);
    });
    process.once("SIGTERM", () => {
      closeStream();
      process.exit(143);
    });
  }

  private log(
    level: "INFO" | "WARN" | "ERROR" | "ATTACK",
    payload: LogPayload,
  ): void {
    const safe = sanitizePayload(payload);

    const logEntry = JSON.stringify({
      timestamp: new Date().toISOString(),
      level,
      ...safe,
    });

    if (this.logStream?.writable) {
      this.logStream.write(logEntry + "\n");
    }

    switch (level) {
      case "ATTACK":
        console.warn(
          `[WAF] 🛑 ATTACK | type=${safe.attackType} | rule=${safe.rule} | ` +
            `ip=${safe.ip} | path=${safe.path} | location=${safe.location} | ` +
            `matched="${safe.matched}"`,
        );
        break;
      case "WARN":
        console.warn(`[WAF]  WARN  | ${safe.message}`);
        break;
      case "ERROR":
        console.error(`[WAF] ERROR  | ${safe.message}`);
        break;
      case "INFO":
      default:
        console.log(`[WAF] INFO  | ${safe.message}`);
        break;
    }
  }

  public info(message: string, meta: Omit<LogPayload, "message"> = {}): void {
    this.log("INFO", { message, ...meta });
  }

  public warn(message: string, meta: Omit<LogPayload, "message"> = {}): void {
    this.log("WARN", { message, ...meta });
  }

  public error(message: string, meta: Omit<LogPayload, "message"> = {}): void {
    this.log("ERROR", { message, ...meta });
  }

  public attack(meta: LogPayload): void {
    this.log("ATTACK", meta);
  }
}

export const logger = new WafLogger();
