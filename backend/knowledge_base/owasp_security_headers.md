# OWASP Secure Headers & Web Application Defensive Guidance

## 1. HTTP Strict Transport Security (HSTS)
- **Header**: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
- **Purpose**: Enforces all future browser connections to use HTTPS instead of HTTP. Prevents SSL stripping man-in-the-middle (MitM) attacks.
- **Remediation**: Set max-age to at least 1 year (31536000 seconds) and ensure all subdomains support HTTPS before applying `includeSubDomains`.

## 2. Content Security Policy (CSP)
- **Header**: `Content-Security-Policy: default-src 'self'; img-src 'self' data: https:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'`
- **Purpose**: Restricts origins from which scripts, styles, images, and frames can load. Primary defense against Cross-Site Scripting (XSS) and data exfiltration.
- **Remediation**: Start with a baseline restrictive policy in report-only mode (`Content-Security-Policy-Report-Only`), monitor violations, then enforce.

## 3. Anti-Clickjacking (X-Frame-Options & CSP frame-ancestors)
- **Header**: `X-Frame-Options: DENY` or `X-Frame-Options: SAMEORIGIN`
- **Purpose**: Prevents malicious sites from embedding your website within an `<iframe>` to trick users into executing unauthorized clicks.
- **Modern Alternative**: `Content-Security-Policy: frame-ancestors 'none';` or `frame-ancestors 'self';`.

## 4. MIME Sniffing Prevention (X-Content-Type-Options)
- **Header**: `X-Content-Type-Options: nosniff`
- **Purpose**: Forces browsers to honor declared Content-Type headers rather than sniffing and executing non-executable files (e.g., executing a user-uploaded image as JavaScript).

## 5. Information Disclosure Reduction (Server / X-Powered-By)
- **Headers to remove**: `Server: Apache/2.4.41 (Ubuntu)`, `X-Powered-By: Express`, `X-AspNet-Version`
- **Risk**: Exposing exact backend server versions assists attackers in selecting targeted exploits.
- **Remediation**: Configure web servers (Nginx: `server_tokens off;`, Apache: `ServerTokens Prod`, Express: `app.disable('x-powered-by')`) to omit or obfuscate these headers.
