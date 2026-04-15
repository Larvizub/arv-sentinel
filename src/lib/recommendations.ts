type RecommendationEntry = {
  recommendation: string;
  reference: string;
};

const RECOMMENDATIONS: Record<string, RecommendationEntry> = {
  transport_https: {
    recommendation:
      "Forzar HTTPS en toda la plataforma, redirigir HTTP a HTTPS y habilitar certificados vigentes con renovacion automatica.",
    reference: "OWASP ASVS V9 - Communications"
  },
  headers_hsts: {
    recommendation:
      "Configurar Strict-Transport-Security con max-age amplio, includeSubDomains y preload cuando sea viable.",
    reference: "OWASP Secure Headers Project - HSTS"
  },
  headers_csp_missing: {
    recommendation:
      "Definir una Content-Security-Policy restrictiva con nonces o hashes y sin comodines inseguros.",
    reference: "OWASP Cheat Sheet - Content Security Policy"
  },
  headers_csp_unsafe: {
    recommendation:
      "Eliminar unsafe-inline y unsafe-eval en CSP; migrar scripts inline a archivos controlados con nonce/hash.",
    reference: "OWASP Cheat Sheet - Content Security Policy"
  },
  headers_xfo: {
    recommendation:
      "Agregar X-Frame-Options DENY/SAMEORIGIN o frame-ancestors en CSP para prevenir clickjacking.",
    reference: "OWASP Clickjacking Defense Cheat Sheet"
  },
  headers_xcto: {
    recommendation:
      "Configurar X-Content-Type-Options: nosniff para bloquear interpretaciones de tipo de contenido ambiguas.",
    reference: "OWASP Secure Headers Project"
  },
  headers_referrer: {
    recommendation:
      "Establecer Referrer-Policy estricta como strict-origin-when-cross-origin o no-referrer.",
    reference: "OWASP Secure Headers Project"
  },
  headers_permissions: {
    recommendation:
      "Aplicar Permissions-Policy para limitar APIs del navegador no necesarias (camera, mic, geolocation, etc.).",
    reference: "OWASP Secure Headers Project"
  },
  cookies_secure: {
    recommendation:
      "Marcar cookies sensibles con Secure y servirlas solo sobre HTTPS.",
    reference: "OWASP Session Management Cheat Sheet"
  },
  cookies_httponly: {
    recommendation:
      "Marcar cookies de sesion/autenticacion con HttpOnly para reducir exfiltracion via XSS.",
    reference: "OWASP Session Management Cheat Sheet"
  },
  cookies_samesite: {
    recommendation:
      "Configurar SameSite=Lax o Strict en cookies sensibles para mitigar CSRF.",
    reference: "OWASP CSRF Prevention Cheat Sheet"
  },
  dom_eval: {
    recommendation:
      "Eliminar eval/new Function y reemplazar con logica segura o parseo estricto de datos.",
    reference: "OWASP JavaScript Security Cheat Sheet"
  },
  dom_document_write: {
    recommendation:
      "Evitar document.write; usar APIs seguras del DOM y escaping contextual.",
    reference: "OWASP DOM based XSS Prevention Cheat Sheet"
  },
  dom_innerhtml: {
    recommendation:
      "Evitar asignaciones a innerHTML con datos dinamicos; usar textContent o sanitizacion robusta.",
    reference: "OWASP DOM based XSS Prevention Cheat Sheet"
  },
  dom_inline_handlers: {
    recommendation:
      "Migrar handlers inline a addEventListener y reforzar CSP para bloquear script inline.",
    reference: "OWASP JavaScript Security Cheat Sheet"
  },
  dom_js_uri: {
    recommendation:
      "Eliminar enlaces javascript: y reemplazarlos con eventos controlados y validacion explicita.",
    reference: "OWASP XSS Prevention Cheat Sheet"
  },
  storage_sensitive: {
    recommendation:
      "No almacenar tokens o secretos en localStorage/sessionStorage; preferir cookies HttpOnly y rotacion de tokens.",
    reference: "OWASP HTML5 Security Cheat Sheet"
  },
  forms_insecure_action: {
    recommendation:
      "Evitar formularios con action HTTP; enviar datos sensibles unicamente sobre HTTPS.",
    reference: "OWASP Transport Layer Security Cheat Sheet"
  },
  forms_password_autocomplete: {
    recommendation:
      "Configurar atributo autocomplete adecuado en campos de password para endurecer UX de autenticacion y gestores de credenciales.",
    reference: "OWASP Authentication Cheat Sheet"
  }
};

const FALLBACK: RecommendationEntry = {
  recommendation:
    "Aplicar hardening por capas: cabeceras, validacion de entrada/salida, control de sesiones y monitoreo continuo.",
  reference: "OWASP ASVS"
};

export function getRecommendation(key: string): RecommendationEntry {
  return RECOMMENDATIONS[key] ?? FALLBACK;
}
