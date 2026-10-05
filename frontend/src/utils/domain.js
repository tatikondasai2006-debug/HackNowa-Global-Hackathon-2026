const DOMAIN_PATTERN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i;

export function sanitizeDomain(raw) {
  if (!raw || typeof raw !== 'string') return '';
  return raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, '')
    .split('/')[0]
    .split('?')[0]
    .split('#')[0]
    .split(':')[0]
    .replace(/\.$/, '');
}

export function isValidDomainFormat(domain) {
  if (!domain) return false;
  if (domain.length < 3 || domain.length > 255) return false;
  return DOMAIN_PATTERN.test(domain);
}

export function domainValidationMessage(domain) {
  if (!domain) return 'Enter a domain name (e.g. company.com).';
  if (!isValidDomainFormat(domain)) {
    return 'Use a public domain such as company.com — no protocol, path, or port.';
  }
  return '';
}
