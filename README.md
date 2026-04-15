# ARV Security Sentinel (Chrome Extension)

Extension de Chrome (Manifest V3) para auditoria defensiva de seguridad web.

## Alcance

Esta extension detecta configuraciones y patrones inseguros observables, por ejemplo:

- Transporte HTTPS/HSTS
- Cabeceras de seguridad (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- Cookies (Secure, HttpOnly, SameSite)
- Senales DOM/JS (eval, new Function, document.write, innerHTML, eventos inline, javascript:)
- Exposicion de claves sensibles en localStorage/sessionStorage
- Formularios con action HTTP

No ejecuta payloads de explotacion ni ataques activos.

## Instalacion

1. Instalar dependencias:

```bash
npm install
```

2. Compilar:

```bash
npm run build
```

3. Cargar en Chrome:

- Abrir `chrome://extensions/`
- Activar "Modo desarrollador"
- Seleccionar "Cargar descomprimida"
- Elegir la carpeta `dist`

## Uso

1. Abre la pagina objetivo (HTTP/HTTPS).
2. Haz clic en la extension.
3. Presiona "Iniciar escaneo".
4. Revisa severidad, evidencia y recomendaciones.

## Estructura

- `manifest.json`: permisos y wiring MV3
- `src/background/service-worker.ts`: orquestacion de auditoria
- `src/content/content-script.ts`: recoleccion de senales del DOM
- `src/lib/recommendations.ts`: recomendaciones OWASP
- `src/lib/scoring.ts`: score y conteos
- `src/popup/*`: interfaz y filtros
- `src/types/*`: contratos compartidos
