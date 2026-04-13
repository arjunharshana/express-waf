export interface WafConfig {
  enabled: boolean;

  // block request if true
  blockMalicious: boolean;

  blockMessage: string;
  statusCode: number;
  inspectionRules: {
    checkBody: boolean;
    checkQuery: boolean;
    checkHeaders: boolean;
  };
}
