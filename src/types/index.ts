export interface WafConfig {
  enabled?: boolean;
  blockMalicious?: boolean;

  blockMessage?: string;
  statusCode?: number;
}
