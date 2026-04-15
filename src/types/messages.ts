import type { AuditReport, PageSignals } from "./security";

export interface RunAuditRequest {
  type: "RUN_AUDIT";
}

export interface CollectPageSignalsRequest {
  type: "COLLECT_PAGE_SIGNALS";
}

export interface RunAuditSuccess {
  ok: true;
  report: AuditReport;
}

export interface RunAuditFailure {
  ok: false;
  error: string;
}

export type RunAuditResponse = RunAuditSuccess | RunAuditFailure;

export interface CollectPageSignalsResponse {
  ok: true;
  signals: PageSignals;
}

export type RuntimeRequest = RunAuditRequest | CollectPageSignalsRequest;
