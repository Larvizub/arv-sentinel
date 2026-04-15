import "./popup.css";
import type { RunAuditResponse } from "../types/messages";
import type { AuditReport, Category, Severity } from "../types/security";

const severityLabels: Record<Severity, string> = {
  critical: "Critica",
  high: "Alta",
  medium: "Media",
  low: "Baja"
};

const severityOptions: Array<{ label: string; value: Severity | "all" }> = [
  { label: "Todas", value: "all" },
  { label: "Critica", value: "critical" },
  { label: "Alta", value: "high" },
  { label: "Media", value: "medium" },
  { label: "Baja", value: "low" }
];

const categoryOptions: Array<{ label: string; value: Category | "all" }> = [
  { label: "Todas las categorias", value: "all" },
  { label: "Transporte", value: "transport" },
  { label: "Cabeceras", value: "headers" },
  { label: "Cookies", value: "cookies" },
  { label: "DOM y Scripts", value: "dom" },
  { label: "Storage", value: "storage" },
  { label: "Formularios", value: "forms" }
];

const appElement = document.querySelector<HTMLDivElement>("#app");

if (!appElement) {
  throw new Error("No se encontro el contenedor principal del popup.");
}

const appRoot: HTMLDivElement = appElement;

const state: {
  loading: boolean;
  report: AuditReport | null;
  statusText: string;
  severityFilter: Severity | "all";
  categoryFilter: Category | "all";
  currentUrl: string;
} = {
  loading: false,
  report: null,
  statusText: "Listo para auditar",
  severityFilter: "all",
  categoryFilter: "all",
  currentUrl: "Sin URL detectada"
};

void bootstrap();

async function bootstrap(): Promise<void> {
  state.currentUrl = await getActiveTabUrl();
  state.report = await loadCachedReport(state.currentUrl);
  if (state.report) {
    state.statusText = "Reporte en cache cargado";
  }
  render();
}

function render(): void {
  appRoot.innerHTML = `
    <main class="shell">
      <header class="header">
        <div>
          <h1 class="brand">ARV Sentinel</h1>
          <p class="brand-sub">Defensive security analyzer</p>
        </div>
        <span class="status-pill">${escapeHtml(state.statusText)}</span>
      </header>

      <section class="controls">
        <div class="url-preview">
          <span class="url-label">URL auditada</span>
          <p class="url-value">${escapeHtml(state.currentUrl)}</p>
        </div>
        <button id="scan-btn" class="scan-button" ${state.loading ? "disabled" : ""}>
          ${state.loading ? "Escaneando..." : "Iniciar escaneo"}
        </button>
      </section>

      ${renderScorePanel()}

      <section class="filter-row">
        <select id="severity-filter" class="select">
          ${severityOptions
            .map(
              (item) =>
                `<option value="${item.value}" ${
                  state.severityFilter === item.value ? "selected" : ""
                }>${item.label}</option>`
            )
            .join("")}
        </select>
        <select id="category-filter" class="select">
          ${categoryOptions
            .map(
              (item) =>
                `<option value="${item.value}" ${
                  state.categoryFilter === item.value ? "selected" : ""
                }>${item.label}</option>`
            )
            .join("")}
        </select>
      </section>

      <section class="findings">
        ${renderFindings()}
      </section>

      ${renderNotes()}
    </main>
  `;

  bindEvents();
}

function renderScorePanel(): string {
  const fallback = {
    score: 100,
    totals: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0
    }
  };

  const source = state.report ?? fallback;

  return `
    <section class="score-panel">
      <article class="score-ring">
        <p class="score-value">${source.score}</p>
        <p class="score-caption">Score / 100</p>
      </article>
      <article class="metrics">
        <div class="metric metric-critical">
          <span class="metric-label">Criticas</span>
          <p class="metric-value">${source.totals.critical}</p>
        </div>
        <div class="metric metric-high">
          <span class="metric-label">Altas</span>
          <p class="metric-value">${source.totals.high}</p>
        </div>
        <div class="metric metric-medium">
          <span class="metric-label">Medias</span>
          <p class="metric-value">${source.totals.medium}</p>
        </div>
        <div class="metric metric-low">
          <span class="metric-label">Bajas</span>
          <p class="metric-value">${source.totals.low}</p>
        </div>
      </article>
    </section>
  `;
}

function renderFindings(): string {
  if (!state.report) {
    return `<div class="empty">Ejecuta un escaneo para listar hallazgos de seguridad y recomendaciones.</div>`;
  }

  const filtered = state.report.findings.filter((finding) => {
    const severityMatch =
      state.severityFilter === "all" || finding.severity === state.severityFilter;
    const categoryMatch =
      state.categoryFilter === "all" || finding.category === state.categoryFilter;
    return severityMatch && categoryMatch;
  });

  if (filtered.length === 0) {
    return `<div class="empty">No hay hallazgos para el filtro seleccionado.</div>`;
  }

  return filtered
    .map(
      (finding) => `
      <article class="card card-${finding.severity}">
        <header class="card-head">
          <h2 class="card-title">${escapeHtml(finding.title)}</h2>
          <span class="badge badge-${finding.severity}">${severityLabels[finding.severity]}</span>
        </header>
        <p class="card-text">${escapeHtml(finding.description)}</p>
        <p class="card-meta"><strong>Impacto:</strong> ${escapeHtml(finding.impact)}</p>
        <p class="card-meta"><strong>Evidencia:</strong> ${escapeHtml(
          finding.evidence ?? "No aplica"
        )}</p>
        <p class="card-meta"><strong>Recomendacion:</strong> ${escapeHtml(
          finding.recommendation
        )}</p>
        <p class="card-meta"><strong>Referencia:</strong> ${escapeHtml(finding.reference)}</p>
      </article>
    `
    )
    .join("");
}

function renderNotes(): string {
  if (!state.report || state.report.notes.length === 0) {
    return "";
  }

  return `
    <section class="notes">
      <p>${escapeHtml(state.report.notes.join(" | "))}</p>
    </section>
  `;
}

function bindEvents(): void {
  const scanButton = document.querySelector<HTMLButtonElement>("#scan-btn");
  const severityFilter = document.querySelector<HTMLSelectElement>("#severity-filter");
  const categoryFilter = document.querySelector<HTMLSelectElement>("#category-filter");

  scanButton?.addEventListener("click", () => {
    void runAudit();
  });

  severityFilter?.addEventListener("change", (event) => {
    const target = event.target as HTMLSelectElement;
    state.severityFilter = target.value as Severity | "all";
    render();
  });

  categoryFilter?.addEventListener("change", (event) => {
    const target = event.target as HTMLSelectElement;
    state.categoryFilter = target.value as Category | "all";
    render();
  });
}

async function runAudit(): Promise<void> {
  state.loading = true;
  state.statusText = "Escaneo defensivo en progreso";
  render();

  let response: RunAuditResponse;
  try {
    response = (await chrome.runtime.sendMessage({
      type: "RUN_AUDIT"
    })) as RunAuditResponse;
  } catch {
    state.loading = false;
    state.statusText = "Error de comunicacion con el motor";
    render();
    return;
  }

  state.loading = false;

  if (!response.ok) {
    state.statusText = response.error;
    render();
    return;
  }

  state.report = response.report;
  state.currentUrl = response.report.url;
  state.statusText = `Escaneo finalizado ${formatShortDate(response.report.scannedAt)}`;
  render();
}

async function getActiveTabUrl(): Promise<string> {
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return activeTab?.url ?? "Sin URL detectada";
}

async function loadCachedReport(url: string): Promise<AuditReport | null> {
  if (!/^https?:\/\//i.test(url)) {
    return null;
  }

  const result = (await chrome.storage.local.get([`lastReport:${url}`])) as Record<
    string,
    AuditReport | undefined
  >;

  return result[`lastReport:${url}`] ?? null;
}

function formatShortDate(isoDate: string): string {
  const date = new Date(isoDate);
  if (Number.isNaN(date.getTime())) {
    return "";
  }

  return date.toLocaleString("es-CR", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit"
  });
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
