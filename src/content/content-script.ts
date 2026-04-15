import type {
  CollectPageSignalsRequest,
  CollectPageSignalsResponse
} from "../types/messages";
import type { PageSignals } from "../types/security";

const SENSITIVE_KEY_PATTERN = /(token|jwt|secret|password|auth|session|apikey|api_key)/i;
const DANGEROUS_SOURCE_PATTERN = {
  evalCalls: /\beval\s*\(/g,
  newFunctionCalls: /new\s+Function\s*\(/g,
  documentWriteCalls: /document\.write\s*\(/g,
  innerHtmlAssignments: /\.innerHTML\s*=/g
};

function countMatches(input: string, pattern: RegExp): number {
  return (input.match(pattern) ?? []).length;
}

function safeStorageKeys(storage: Storage): string[] {
  try {
    const keys: string[] = [];
    for (let index = 0; index < storage.length; index += 1) {
      const key = storage.key(index);
      if (key && SENSITIVE_KEY_PATTERN.test(key)) {
        keys.push(key);
      }
    }
    return keys;
  } catch {
    return [];
  }
}

function getInlineScriptSource(): string {
  const inlineScripts = Array.from(
    document.querySelectorAll<HTMLScriptElement>("script:not([src])")
  );

  return inlineScripts
    .map((scriptElement) => scriptElement.textContent ?? "")
    .join("\n");
}

function collectSignals(): PageSignals {
  const inlineSource = getInlineScriptSource();

  const inlineEventHandlers = document.querySelectorAll(
    "[onclick],[onerror],[onload],[onmouseover],[onsubmit],[onchange]"
  ).length;

  const javascriptUriLinks = document.querySelectorAll(
    "a[href^='javascript:']"
  ).length;

  const passwordInputsWithoutAutocomplete = Array.from(
    document.querySelectorAll<HTMLInputElement>("input[type='password']")
  ).filter((input) => {
    const autocomplete = (input.getAttribute("autocomplete") ?? "").trim();
    return autocomplete.length === 0;
  }).length;

  const insecureFormActions = Array.from(
    document.querySelectorAll<HTMLFormElement>("form[action]")
  ).filter((form) => form.action.startsWith("http://")).length;

  const sensitiveStorageKeys = [
    ...safeStorageKeys(window.localStorage),
    ...safeStorageKeys(window.sessionStorage)
  ];

  return {
    inlineEventHandlers,
    javascriptUriLinks,
    dangerousPatterns: {
      evalCalls: countMatches(inlineSource, DANGEROUS_SOURCE_PATTERN.evalCalls),
      newFunctionCalls: countMatches(
        inlineSource,
        DANGEROUS_SOURCE_PATTERN.newFunctionCalls
      ),
      documentWriteCalls: countMatches(
        inlineSource,
        DANGEROUS_SOURCE_PATTERN.documentWriteCalls
      ),
      innerHtmlAssignments: countMatches(
        inlineSource,
        DANGEROUS_SOURCE_PATTERN.innerHtmlAssignments
      )
    },
    passwordInputsWithoutAutocomplete,
    insecureFormActions,
    sensitiveStorageKeys
  };
}

chrome.runtime.onMessage.addListener(
  (
    message: CollectPageSignalsRequest,
    _sender,
    sendResponse: (response: CollectPageSignalsResponse) => void
  ) => {
    if (message.type !== "COLLECT_PAGE_SIGNALS") {
      return;
    }

    const signals = collectSignals();
    sendResponse({ ok: true, signals });
  }
);
