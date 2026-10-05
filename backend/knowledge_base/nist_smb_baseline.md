# NIST Cybersecurity Framework & Small Business Hardening Baseline

## 1. Identity & Access Management for Domain Assets
Small and medium businesses must ensure domain registrar accounts, DNS zone managers, and hosting providers use multi-factor authentication (MFA) and distinct administrative credentials.

## 2. Transport Layer Security (TLS/SSL) Best Practices
- **Protocols**: Always disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 due to known cryptographic weaknesses (POODLE, BEAST, SWEET32). Standard baseline is TLS 1.2 and TLS 1.3.
- **Certificate Validity**: SSL/TLS certificates should be renewed at least 30 days before expiration. Automated issuance (e.g., ACME / Let's Encrypt) is recommended.
- **Certificate Authority Authorization (CAA)**: Publish DNS CAA records to explicitly authorize specific Certificate Authorities (e.g., letsencrypt.org, digicert.com) to issue certificates for your domain, mitigating unauthorized certificate issuance.

## 3. Email Authentication & Anti-Spoofing (SPF, DKIM, DMARC)
- **SPF (Sender Policy Framework)**: A TXT record defining which IP addresses and mail relays may send email on behalf of your domain. Never end with `+all` (which allows anyone to send). Use `~all` (SoftFail) or `-all` (HardFail).
- **DKIM (DomainKeys Identified Mail)**: Cryptographic signature added to email headers that verifies the email message was not modified in transit.
- **DMARC (Domain-based Message Authentication, Reporting, and Conformance)**: Uses SPF and DKIM to determine email authenticity. Policies:
  - `p=none`: Monitoring mode only; reports are sent but unauthorized emails are delivered.
  - `p=quarantine`: Suspicious emails are routed to spam/junk folders.
  - `p=reject`: Highest protection; unauthorized emails are rejected outright by receiving mail transfer agents.
