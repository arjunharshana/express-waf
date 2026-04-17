# express-waf

A powerful, zero-dependency Web Application Firewall (WAF) and Runtime Application Self-Protection (RASP) middleware designed specifically for Express.js applications.

`express-waf` provides out-of-the-box protection against the most common and critical web vulnerabilities, allowing you to secure your backend routes with just a few lines of code. Whether you need global traffic filtering or granular, route-specific payload inspection, this package delivers enterprise-grade security without sacrificing event-loop performance.

## Installation

```bash
npm install express-waf
```

---

## Quick Start

The easiest way to protect your application is to apply the global `createWaf()` middleware to your entire Express app.

```typescript
import express from "express";
import { createWaf } from "express-waf";

const app = express();

app.use(express.json());

app.use(
  createWaf({
    // your configuration options here
  }),
);
```

---

## Why express-waf?

- 🛡️ **Easy to integrate** — drop it in as standard Express middleware
- ⚙️ **Configurable** — tailor rules to your application's needs
- 🚀 **Lightweight** — minimal overhead on your request pipeline

---

## Traffic Control (IP Management & Rate Limiting)

Stop DDoS attempts and block known bad actors before they even reach your core application logic.

```typescript
import { ipManager, rateLimiter } from "express-waf";

// Bypass the WAF for internal services, block known threats.
app.use(
  ipManager({
    whitelist: ["10.0.0.*", "127.0.0.1"], // Supports wildcard subnets
    blacklist: ["203.0.113.5"],
  }),
);

// Stop brute-force attacks with a Penalty Box.
app.use(
  rateLimiter({
    windowMs: 60 * 1000, // 1 minute window
    maxRequests: 100, // Limit each IP to 100 requests per window
    blockDurationMs: 15 * 60 * 1000, // 15-minute complete ban if they exceed the limit
  }),
);
```

---

## Active Defense

Hook into the WAF's event lifecycle to trigger real-time SecOps alerts or alter database states.

```typescript
import { wafEvents, logger } from "express-waf";

wafEvents.on("attack", async (data) => {
  console.log(`Attack Blocked: ${data.attackType} from ${data.ip}`);

  if (data.attackType === "NoSQLi") {
    // Example: Instantly lock the targeted user account in your database
    // await db.users.updateOne({ lastIp: data.ip }, { $set: { locked: true }});
  }
});

wafEvents.on("rateLimit", (data) => {
  // Example: Send a Slack webhook to your engineering team
  // await sendSlackAlert(`Traffic spike detected from ${data.ip}`);
});
```

---

## Granular Route Protection

You can bypass the master engine and apply specific middlewares only where they are needed.

```typescript
import {
  sqliMiddleware,
  xssMiddleware,
  nosqliMiddleware,
  lfiMiddleware,
} from "express-waf";

// Only check for NoSQL Injection on the database-heavy login route
app.post("/auth/login", nosqliMiddleware(), loginController);

// Only check for Path Traversal on the file download route
app.get("/files/download", lfiMiddleware(), downloadController);

// Only check for Cross-Site Scripting on the user-generated content route
app.post("/blog/comments", xssMiddleware(), commentController);
```

---

## Structured Telemetry

All WAF interactions are logged via non-blocking I/O to `logs/waf-security.log` in standard JSON format, making it instantly compatible with SIEM tools like **Splunk**, **Datadog**, or **ELK**. Log forging (injection via `\n`) is automatically stripped.

```json
{
  "timestamp": "2026-04-17T14:27:28.000Z",
  "level": "ATTACK",
  "attackType": "SQLi",
  "rule": "STACKED_QUERIES",
  "ip": "::1",
  "path": "/api/users",
  "matched": "'; DROP TABLE users"
}
```

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](./LICENSE) file for details.
