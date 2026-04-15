export type Severity = "critical" | "high" | "medium" | "low";

export type Category =
  | "transport"
  | "headers"
  | "cookies"
  | "dom"
  | "storage"
  | "forms";

export interface Finding {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: Category;
  impact: string;
  recommendation: string;
  reference: string;
  evidence?: string;
}

export interface SeverityCount {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface AuditReport {
  url: string;
  scannedAt: string;
  score: number;
  totals: SeverityCount;
  findings: Finding[];
  notes: string[];
}

export interface PageSignals {
  inlineEventHandlers: number;
  javascriptUriLinks: number;
  dangerousPatterns: {
    evalCalls: number;
    newFunctionCalls: number;
    documentWriteCalls: number;
    innerHtmlAssignments: number;
  };
  passwordInputsWithoutAutocomplete: number;
  insecureFormActions: number;
  sensitiveStorageKeys: string[];
}
