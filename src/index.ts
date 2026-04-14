import e from "express";

export * from "./types";
export { createWaf } from "./middleware/waf";

export { sqliMiddleware } from "./middleware/sqlimiddleware";
export { xssMiddleware } from "./middleware/xssmiddleware";
export { nosqliMiddleware } from "./middleware/nosqslimiddleware";

export { detectSQLi } from "./detectors/sqli";
export { detectXSS } from "./detectors/xss";
export { detectNoSQLi } from "./detectors/nosqli";

export const expressWaf = () => {
  console.log("WAF initialized!");
};
