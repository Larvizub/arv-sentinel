import type { Finding, Severity, SeverityCount } from "../types/security";

const PENALTY_BY_SEVERITY: Record<Severity, number> = {
  critical: 30,
  high: 18,
  medium: 10,
  low: 5
};

export function getSeverityCounts(findings: Finding[]): SeverityCount {
  return findings.reduce<SeverityCount>(
    (acc, finding) => {
      acc[finding.severity] += 1;
      return acc;
    },
    {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    }
  );
}

export function calculateScore(findings: Finding[]): number {
  const penalty = findings.reduce(
    (sum, finding) => sum + PENALTY_BY_SEVERITY[finding.severity],
    0
  );

  const rawScore = 100 - penalty;
  return Math.max(0, Math.min(100, rawScore));
}

const ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3
};

export function sortFindingsBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
}
