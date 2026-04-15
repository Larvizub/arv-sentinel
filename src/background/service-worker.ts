import { calculateScore, getSeverityCounts, sortFindingsBySeverity } from "../lib/scoring";
import { getRecommendation } from "../lib/recommendations";
import type {
  CollectPageSignalsResponse,
  RunAuditRequest,
  RunAuditResponse
} from "../types/messages";
import type { AuditReport, Finding, PageSignals, Severity } from "../types/security";

const STORAGE_REPORT_PREFIX = "lastReport:";

const EMPTY_PAGE_SIGNALS: PageSignals = {
  inlineEventHandlers: 0,
  javascriptUriLinks: 0,
  dangerousPatterns: {
    evalCalls: 0,
    newFunctionCalls: 0,
    documentWriteCalls: 0,
    innerHtmlAssignments: 0
  },
  passwordInputsWithoutAutocomplete: 0,
  insecureFormActions: 0,
  sensitiveStorageKeys: []
};

type HeaderMap = Record<string, string | undefined>;

chrome.runtime.onMessage.addListener(
  (
    message: RunAuditRequest,
    _sender,
    sendResponse: (response: RunAuditResponse) => void
  ) => {
    if (message.type !== "RUN_AUDIT") {
      return;
    }

    void runAudit()
      .then((response) => sendResponse(response))
      .catch((error: unknown) => {
        const reason = error instanceof Error ? error.message : "Error desconocido";
        sendResponse({ ok: false, error: reason });
      });

    return true;
  }
);

async function runAudit(): Promise<RunAuditResponse> {
  const [activeTab] = await chrome.tabs.query({ active: true, currentWindow: true });

  if (!activeTab?.id || !activeTab.url) {
    return { ok: false, error: "No se pudo identificar la pestaña activa." };
  }

  if (!/^https?:\/\//i.test(activeTab.url)) {
    return {
      ok: false,
      error: "Solo se pueden auditar paginas HTTP/HTTPS en la pestaña activa."
    };
  }

  const [headerResult, cookieFindings, signalResult] = await Promise.all([
    auditHeaders(activeTab.url),
    auditCookies(activeTab.url),
    auditPageSignals(activeTab.id)
  ]);

  const notes = [...headerResult.notes, ...signalResult.notes];

  const findings = sortFindingsBySeverity([
    ...headerResult.findings,
    ...cookieFindings,
    ...signalResult.findings
  ]);

  const report: AuditReport = {
    url: activeTab.url,
    scannedAt: new Date().toISOString(),
    score: calculateScore(findings),
    totals: getSeverityCounts(findings),
    findings,
    notes
  };

  await chrome.storage.local.set({ [`${STORAGE_REPORT_PREFIX}${activeTab.url}`]: report });

  return {
    ok: true,
    report
  };
}

async function auditHeaders(
  url: string
): Promise<{ findings: Finding[]; notes: string[] }> {
  const findings: Finding[] = [];
  const notes: string[] = [];

  const parsedUrl = new URL(url);

  if (parsedUrl.protocol !== "https:") {
    findings.push(
      buildFinding({
        id: "transport_http",
        title: "Sitio servido sin HTTPS",
        description:
          "El sitio auditado responde sobre HTTP, lo que expone el trafico a interceptacion.",
        severity: "critical",
        category: "transport",
        impact: "Riesgo de MITM, robo de sesion y manipulacion de contenido en transito.",
        evidence: parsedUrl.href,
        recommendationKey: "transport_https"
      })
    );

    return { findings, notes };
  }

  let response: Response;
  try {
    response = await fetch(url, {
      method: "GET",
      cache: "no-store",
      redirect: "follow"
    });
  } catch {
    notes.push("No se pudo recuperar la respuesta HTTP para inspeccionar cabeceras.");
    return { findings, notes };
  }

  const headerMap: HeaderMap = {
    hsts: response.headers.get("strict-transport-security") ?? undefined,
    csp: response.headers.get("content-security-policy") ?? undefined,
    xfo: response.headers.get("x-frame-options") ?? undefined,
    xcto: response.headers.get("x-content-type-options") ?? undefined,
    referrerPolicy: response.headers.get("referrer-policy") ?? undefined,
    permissionsPolicy: response.headers.get("permissions-policy") ?? undefined,
    server: response.headers.get("server") ?? undefined
  };

  if (!headerMap.hsts) {
    findings.push(
      buildFinding({
        id: "headers_hsts_missing",
        title: "HSTS no configurado",
        description:
          "La cabecera Strict-Transport-Security no esta presente en la respuesta principal.",
        severity: "high",
        category: "headers",
        impact:
          "Permite downgrade o acceso inicial por HTTP en escenarios de ataque de red.",
        recommendationKey: "headers_hsts"
      })
    );
  }

  if (!headerMap.csp) {
    findings.push(
      buildFinding({
        id: "headers_csp_missing",
        title: "Content-Security-Policy ausente",
        description:
          "No se detecto cabecera CSP en la respuesta principal.",
        severity: "high",
        category: "headers",
        impact:
          "Mayor superficie para XSS y carga de recursos no confiables.",
        recommendationKey: "headers_csp_missing"
      })
    );
  } else {
    const hasUnsafeInline = /unsafe-inline/i.test(headerMap.csp);
    const hasUnsafeEval = /unsafe-eval/i.test(headerMap.csp);

    if (hasUnsafeInline || hasUnsafeEval) {
      findings.push(
        buildFinding({
          id: "headers_csp_unsafe",
          title: "CSP permite directivas inseguras",
          description:
            "La politica CSP contiene unsafe-inline y/o unsafe-eval.",
          severity: "medium",
          category: "headers",
          impact:
            "Reduce significativamente la efectividad de CSP frente a inyeccion de scripts.",
          evidence: headerMap.csp,
          recommendationKey: "headers_csp_unsafe"
        })
      );
    }
  }

  if (!headerMap.xfo) {
    findings.push(
      buildFinding({
        id: "headers_xfo_missing",
        title: "X-Frame-Options ausente",
        description:
          "No se detecto proteccion explicita contra framing/clickjacking.",
        severity: "medium",
        category: "headers",
        impact: "La aplicacion puede ser embebida en iframes maliciosos.",
        recommendationKey: "headers_xfo"
      })
    );
  }

  if (!headerMap.xcto) {
    findings.push(
      buildFinding({
        id: "headers_xcto_missing",
        title: "X-Content-Type-Options ausente",
        description:
          "No se encontro X-Content-Type-Options: nosniff en la respuesta.",
        severity: "medium",
        category: "headers",
        impact:
          "El navegador puede interpretar tipos MIME de forma flexible y aumentar riesgo de ejecucion no esperada.",
        recommendationKey: "headers_xcto"
      })
    );
  }

  if (!headerMap.referrerPolicy) {
    findings.push(
      buildFinding({
        id: "headers_referrer_policy_missing",
        title: "Referrer-Policy ausente",
        description:
          "No se encontro una politica de referencia explicita.",
        severity: "low",
        category: "headers",
        impact: "Potencial fuga de informacion en URLs de referencia.",
        recommendationKey: "headers_referrer"
      })
    );
  }

  if (!headerMap.permissionsPolicy) {
    findings.push(
      buildFinding({
        id: "headers_permissions_policy_missing",
        title: "Permissions-Policy ausente",
        description:
          "No se encontro una politica para restringir APIs del navegador.",
        severity: "low",
        category: "headers",
        impact:
          "Mayor superficie de abuso de capacidades como camara, microfono y geolocalizacion.",
        recommendationKey: "headers_permissions"
      })
    );
  }

  if (headerMap.server && /\d/.test(headerMap.server)) {
    findings.push(
      buildFinding({
        id: "headers_server_disclosure",
        title: "Cabecera Server expone version",
        description:
          "La cabecera Server parece revelar informacion de version del backend.",
        severity: "low",
        category: "headers",
        impact:
          "Facilita reconocimiento tecnologico y priorizacion de exploits conocidos.",
        evidence: headerMap.server,
        recommendationKey: "headers_permissions"
      })
    );
  }

  return { findings, notes };
}

async function auditCookies(url: string): Promise<Finding[]> {
  try {
    const cookies = await chrome.cookies.getAll({ url });

    if (cookies.length === 0) {
      return [];
    }

    const findings: Finding[] = [];

    const insecureCookies = cookies.filter((cookie) => !cookie.secure);
    if (insecureCookies.length > 0) {
      findings.push(
        buildFinding({
          id: "cookies_missing_secure",
          title: "Cookies sin atributo Secure",
          description:
            "Se detectaron cookies sin atributo Secure en un contexto autenticable.",
          severity: "high",
          category: "cookies",
          impact: "Las cookies pueden exponerse en canales no cifrados o ataques de downgrade.",
          evidence: summarizeCookieNames(insecureCookies.map((cookie) => cookie.name)),
          recommendationKey: "cookies_secure"
        })
      );
    }

    const sensitiveNamePattern = /(session|token|auth|jwt|sid)/i;
    const sensitiveWithoutHttpOnly = cookies.filter(
      (cookie) => sensitiveNamePattern.test(cookie.name) && !cookie.httpOnly
    );

    if (sensitiveWithoutHttpOnly.length > 0) {
      findings.push(
        buildFinding({
          id: "cookies_missing_httponly",
          title: "Cookies sensibles sin HttpOnly",
          description:
            "Cookies de sesion/autenticacion accesibles por JavaScript del navegador.",
          severity: "high",
          category: "cookies",
          impact: "En presencia de XSS, los tokens pueden ser exfiltrados facilmente.",
          evidence: summarizeCookieNames(
            sensitiveWithoutHttpOnly.map((cookie) => cookie.name)
          ),
          recommendationKey: "cookies_httponly"
        })
      );
    }

    const laxPolicies = cookies.filter(
      (cookie) => cookie.sameSite === "no_restriction"
    );

    if (laxPolicies.length > 0) {
      findings.push(
        buildFinding({
          id: "cookies_samesite_weak",
          title: "Cookies con SameSite=None",
          description:
            "Algunas cookies usan SameSite=None, ampliando escenarios de envio cross-site.",
          severity: "medium",
          category: "cookies",
          impact: "Incrementa exposicion ante ataques CSRF si no hay controles compensatorios.",
          evidence: summarizeCookieNames(laxPolicies.map((cookie) => cookie.name)),
          recommendationKey: "cookies_samesite"
        })
      );
    }

    return findings;
  } catch {
    return [];
  }
}

async function auditPageSignals(
  tabId: number
): Promise<{ findings: Finding[]; notes: string[] }> {
  const notes: string[] = [];

  let signals = EMPTY_PAGE_SIGNALS;
  try {
    const response = (await chrome.tabs.sendMessage(tabId, {
      type: "COLLECT_PAGE_SIGNALS"
    })) as CollectPageSignalsResponse;

    if (response?.ok) {
      signals = response.signals;
    }
  } catch {
    notes.push(
      "No fue posible obtener todas las senales del DOM (puede ocurrir en paginas protegidas o especiales del navegador)."
    );
  }

  const findings: Finding[] = [];

  if (signals.inlineEventHandlers > 0) {
    findings.push(
      buildFinding({
        id: "dom_inline_handlers",
        title: "Eventos inline detectados",
        description:
          "Se detectaron atributos inline como onclick/onerror en el DOM.",
        severity: "low",
        category: "dom",
        impact:
          "Complican la aplicacion de CSP estricta y pueden amplificar riesgos de inyeccion.",
        evidence: `${signals.inlineEventHandlers} nodos`,
        recommendationKey: "dom_inline_handlers"
      })
    );
  }

  if (signals.javascriptUriLinks > 0) {
    findings.push(
      buildFinding({
        id: "dom_js_uri_links",
        title: "Enlaces javascript: detectados",
        description:
          "Se encontraron enlaces que usan el esquema javascript: en href.",
        severity: "medium",
        category: "dom",
        impact:
          "Puede habilitar ejecucion de codigo en contextos no previstos y aumentar riesgo XSS.",
        evidence: `${signals.javascriptUriLinks} enlaces`,
        recommendationKey: "dom_js_uri"
      })
    );
  }

  if (signals.dangerousPatterns.evalCalls + signals.dangerousPatterns.newFunctionCalls > 0) {
    findings.push(
      buildFinding({
        id: "dom_eval_usage",
        title: "Uso de eval/new Function en scripts inline",
        description:
          "Se detectaron patrones de ejecucion dinamica de codigo en scripts inline.",
        severity: "high",
        category: "dom",
        impact: "Aumenta significativamente la superficie para DOM XSS y RCE en cliente.",
        evidence: `eval=${signals.dangerousPatterns.evalCalls}, new Function=${signals.dangerousPatterns.newFunctionCalls}`,
        recommendationKey: "dom_eval"
      })
    );
  }

  if (signals.dangerousPatterns.documentWriteCalls > 0) {
    findings.push(
      buildFinding({
        id: "dom_document_write_usage",
        title: "Uso de document.write detectado",
        description:
          "Se encontro uso de document.write en scripts inline.",
        severity: "medium",
        category: "dom",
        impact: "Incrementa riesgo de inyeccion de contenido inseguro durante renderizado.",
        evidence: `${signals.dangerousPatterns.documentWriteCalls} coincidencias`,
        recommendationKey: "dom_document_write"
      })
    );
  }

  if (signals.dangerousPatterns.innerHtmlAssignments > 0) {
    findings.push(
      buildFinding({
        id: "dom_innerhtml_usage",
        title: "Asignaciones a innerHTML detectadas",
        description:
          "Se detectaron asignaciones a innerHTML en scripts inline.",
        severity: "medium",
        category: "dom",
        impact: "Puede derivar en DOM XSS si el contenido no es sanitizado correctamente.",
        evidence: `${signals.dangerousPatterns.innerHtmlAssignments} coincidencias`,
        recommendationKey: "dom_innerhtml"
      })
    );
  }

  if (signals.sensitiveStorageKeys.length > 0) {
    findings.push(
      buildFinding({
        id: "storage_sensitive_keys",
        title: "Claves sensibles en Web Storage",
        description:
          "Se detectaron posibles claves sensibles en localStorage/sessionStorage.",
        severity: "high",
        category: "storage",
        impact: "Exposicion potencial de secretos ante XSS o extensiones maliciosas.",
        evidence: summarizeStorageKeys(signals.sensitiveStorageKeys),
        recommendationKey: "storage_sensitive"
      })
    );
  }

  if (signals.insecureFormActions > 0) {
    findings.push(
      buildFinding({
        id: "forms_http_action",
        title: "Formularios enviando por HTTP",
        description:
          "Se encontraron formularios con action en HTTP.",
        severity: "critical",
        category: "forms",
        impact: "Credenciales y datos sensibles pueden viajar sin cifrado.",
        evidence: `${signals.insecureFormActions} formularios`,
        recommendationKey: "forms_insecure_action"
      })
    );
  }

  if (signals.passwordInputsWithoutAutocomplete > 0) {
    findings.push(
      buildFinding({
        id: "forms_password_without_autocomplete",
        title: "Campos password sin autocomplete explicito",
        description:
          "Se detectaron inputs de password sin atributo autocomplete definido.",
        severity: "low",
        category: "forms",
        impact:
          "Dificulta controles modernos de credenciales y consistencia de politicas de autenticacion.",
        evidence: `${signals.passwordInputsWithoutAutocomplete} inputs`,
        recommendationKey: "forms_password_autocomplete"
      })
    );
  }

  return { findings, notes };
}

function buildFinding(input: {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  category: Finding["category"];
  impact: string;
  recommendationKey: string;
  evidence?: string;
}): Finding {
  const { recommendation, reference } = getRecommendation(input.recommendationKey);

  return {
    id: input.id,
    title: input.title,
    description: input.description,
    severity: input.severity,
    category: input.category,
    impact: input.impact,
    recommendation,
    reference,
    evidence: input.evidence
  };
}

function summarizeCookieNames(names: string[]): string {
  const unique = Array.from(new Set(names));
  const sample = unique.slice(0, 8);
  const remainder = unique.length - sample.length;

  if (remainder > 0) {
    return `${sample.join(", ")} y ${remainder} mas`;
  }

  return sample.join(", ");
}

function summarizeStorageKeys(keys: string[]): string {
  const unique = Array.from(new Set(keys));
  const sample = unique.slice(0, 8);
  const remainder = unique.length - sample.length;

  if (remainder > 0) {
    return `${sample.join(", ")} y ${remainder} mas`;
  }

  return sample.join(", ");
}
