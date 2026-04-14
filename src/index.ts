export * from "./types";
export { createWaf } from "./middleware/waf";

export { sqliMiddleware } from "./middleware/sqlimiddleware";
export { xssMiddleware } from "./middleware/xssmiddleware";

export { detectSQLi } from "./detectors/sqli";
export { detectXSS } from "./detectors/xss";

export const expressWaf = () => {
  console.log("WAF initialized!");
};
