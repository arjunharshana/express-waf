// examples/demo-app.ts

import express, { Request, Response } from "express";
import { createWaf, rateLimiter, ipManager, wafEvents, logger } from "../src";

const app = express();

// Parse incoming JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

wafEvents.on("attack", (data) => {
  logger.info(
    `[WEBHOOK SIMULATION] Alert: ${data.attackType} attempt blocked from ${data.ip} on ${data.path}`,
  );
});

wafEvents.on("rateLimit", (data) => {
  logger.info(
    `[WEBHOOK SIMULATION] Throttling aggressive user: ${data.ip} (${data.requestCount} requests)`,
  );
});

wafEvents.on("blacklistedIp", (data) => {
  logger.info(
    `[WEBHOOK SIMULATION] Dropped connection from known bad actor: ${data.ip}`,
  );
});

app.use(
  ipManager({
    whitelist: ["10.0.0.*"], // Internal microservices bypass the WAF
    blacklist: ["203.0.113.5"], // Known botnet IPs are dropped instantly
    blockMessage: "Access permanently denied.",
  }),
);

app.use(
  rateLimiter({
    maxRequests: 10,
    windowMs: 60 * 1000,
    blockDurationMs: 5 * 1000,
    message: "Too many requests.",
  }),
);

app.use(
  createWaf({
    enabled: true,
    blockMalicious: true,
    statusCode: 403,
    blockMessage: "WAF: Malicious payload detected and blocked.",
    inspectionRules: {
      checkBody: true,
      checkQuery: true,
      checkHeaders: true,
    },
  }),
);

app.post("/api/auth/login", (req: Request, res: Response) => {
  const { username, password } = req.body;

  res.json({
    success: true,
    message: `Authentication successful. Welcome, ${typeof username === "string" ? username : "Admin"}!`,
  });
});

app.post("/api/blog/comment", (req: Request, res: Response) => {
  const { comment } = req.body;

  res.json({
    success: true,
    message: `Comment saved successfully: ${comment}`,
  });
});

app.get("/api/system/download", (req: Request, res: Response) => {
  const { file } = req.query;

  res.json({
    success: true,
    message: `Downloading file stream for: ${file}`,
  });
});

app.get("/api/public/status", (req: Request, res: Response) => {
  res.json({ success: true, message: "Systems operational." });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(
    `\n Express WAF Demo Server running on http://localhost:${PORT}\n`,
  );
  console.log(`--- HOW TO ATTACK THIS SERVER ---`);
  console.log(
    `1. NoSQLi: curl -X POST http://localhost:3000/api/auth/login -H "Content-Type: application/json" -d '{"username": {"$ne": null}}'`,
  );
  console.log(
    `2. XSS:    curl -X POST http://localhost:3000/api/blog/comment -H "Content-Type: application/json" -d '{"comment": "<img src=x onerror=alert(1)>"}'`,
  );
  console.log(
    `3. LFI:    curl "http://localhost:3000/api/system/download?file=../../../../etc/passwd"`,
  );
  console.log(
    `4. DDoS:   Run 'curl http://localhost:3000/api/public/status' 11 times fast!`,
  );
  console.log(`---------------------------------\n`);
});
