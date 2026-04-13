export * from "./types";
export { createWaf } from "./middleware/waf";

export const expressWaf = () => {
  console.log("WAF initialized!");
};
