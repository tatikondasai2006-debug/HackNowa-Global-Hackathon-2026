/**
 * CyberSentinel API Client Service
 * All dashboard and scan UI data comes from these backend endpoints.
 */

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

function formatApiDetail(detail, fallback = 'An unexpected API error occurred') {
  if (!detail) return fallback;
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        if (typeof item === 'string') return item;
        if (item && typeof item.msg === 'string') {
          const loc = Array.isArray(item.loc)
            ? item.loc.filter((part) => part !== 'body' && part !== 'query').join('.')
            : '';
          return loc ? `${loc}: ${item.msg}` : item.msg;
        }
        return null;
      })
      .filter(Boolean);
    return messages.length ? messages.join('; ') : fallback;
  }
  if (typeof detail === 'object' && typeof detail.msg === 'string') {
    return detail.msg;
  }
  return fallback;
}

const TOKEN_KEY = 'cybersentinel_token';
const LEGACY_TOKEN_KEYS = ['cybersentinel_token'];

/**
 * The JWT is held in a module variable and mirrored into sessionStorage.
 *
 * localStorage was previously used, which keeps the token on disk for the
 * lifetime of the origin: any XSS on the origin, any browser extension, and
 * anyone with filesystem access to the profile could read it, and it survived
 * closing the browser. sessionStorage is scoped to the tab and dropped when it
 * closes, and the in-memory copy is never written to disk at all.
 *
 * Residual risk: an XSS payload running on the origin can still read the token
 * from memory while the tab is open. That is inherent to a bearer token in a
 * browser; the mitigation is a strict CSP plus keeping third-party script out of
 * the page. httpOnly cookies would remove this class of risk entirely but
 * require CSRF protection and are out of scope for this change.
 */
class TokenStore {
  constructor() {
    this.token = null;
    this.restore();
  }

  restore() {
    try {
      this.token = window.sessionStorage.getItem(TOKEN_KEY);
    } catch {
      // Storage can be blocked (private mode, disabled cookies). The in-memory
      // copy still works for the lifetime of the page.
      this.token = null;
    }
    this.purgeLegacyStorage();
  }

  purgeLegacyStorage() {
    // A token written by an older build into localStorage would otherwise stay
    // readable there forever, even after this update.
    try {
      LEGACY_TOKEN_KEYS.forEach((key) => window.localStorage.removeItem(key));
    } catch {
      // Ignore: nothing to clean up if storage is unavailable.
    }
  }

  get() {
    if (!this.token) this.restore();
    return this.token;
  }

  set(token) {
    this.token = token || null;
    try {
      if (token) {
        window.sessionStorage.setItem(TOKEN_KEY, token);
      } else {
        window.sessionStorage.removeItem(TOKEN_KEY);
      }
    } catch {
      // Keep the in-memory token even if persistence fails.
    }
    if (!token) this.purgeLegacyStorage();
  }

  clear() {
    this.set(null);
  }
}

const tokenStore = new TokenStore();

class ApiService {
  getToken() {
    return tokenStore.get();
  }

  setToken(token) {
    tokenStore.set(token);
  }

  async request(endpoint, options = {}) {
    const token = this.getToken();
    const headers = {
      ...(options.body instanceof FormData ? {} : { 'Content-Type': 'application/json' }),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    };

    const config = {
      ...options,
      headers,
    };

    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, config);

      if (response.status === 401) {
        this.setToken(null);
        window.dispatchEvent(new Event('auth:unauthorized'));
      }

      if (response.status === 204) {
        return null;
      }

      let data = null;
      try {
        data = await response.json();
      } catch {
        if (!response.ok) {
          throw new Error('An unexpected API error occurred');
        }
        throw new Error('The server returned an invalid response');
      }

      if (!response.ok) {
        throw new Error(formatApiDetail(data?.detail));
      }
      return data;
    } catch (error) {
      if (error instanceof TypeError) {
        throw new Error('Cannot reach the API. Confirm the backend is running on port 8000.');
      }
      throw error;
    }
  }

  async requestBlob(endpoint, fallbackName) {
    const token = this.getToken();
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });

    if (response.status === 401) {
      this.setToken(null);
      window.dispatchEvent(new Event('auth:unauthorized'));
    }

    if (!response.ok) {
      let message = 'Failed to download file';
      try {
        const data = await response.json();
        message = formatApiDetail(data?.detail, message);
      } catch {
        // Non-JSON error body
      }
      throw new Error(message);
    }

    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = fallbackName;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }

  async login(email, password) {
    const data = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    this.setToken(data.access_token);
    return data;
  }

  async register(payload) {
    const data = await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    this.setToken(data.access_token);
    return data;
  }

  async getProfile() {
    return this.request('/auth/me');
  }

  logout() {
    this.setToken(null);
  }
  async validateDomain(domain, resolveDns = true) {
    return this.request('/scans/validate', {
      method: 'POST',
      body: JSON.stringify({ target_domain: domain, resolve_dns: resolveDns }),
    });
  }

  async startScan(domain, options = null, authorizationConfirmed = false) {
    return this.request('/scans/', {
      method: 'POST',
      body: JSON.stringify({
        target_domain: domain,
        scan_options: options,
        authorization_confirmed: Boolean(authorizationConfirmed),
      }),
    });
  }

  async getScans(page = 1, pageSize = 20, filters = {}) {
    const params = new URLSearchParams({
      page: String(page),
      page_size: String(pageSize),
    });
    if (filters.domain) params.set('domain', filters.domain);
    if (filters.status) params.set('status', filters.status);
    return this.request(`/scans/?${params.toString()}`);
  }

  async getDomainHistory(domain, pageSize = 20) {
    return this.request(`/scans/history/${encodeURIComponent(domain)}?page_size=${pageSize}`);
  }

  async compareScans(scanIdA, scanIdB) {
    return this.request(`/scans/compare/${scanIdA}/${scanIdB}`);
  }

  async getScanDetail(scanId) {
    return this.request(`/scans/${scanId}`);
  }

  async getScanStatus(scanId) {
    return this.request(`/scans/${scanId}/status`);
  }

  async getRecommendations(scanId) {
    return this.request(`/scans/${scanId}/recommendations`);
  }

  async deleteScan(scanId) {
    return this.request(`/scans/${scanId}`, { method: 'DELETE' });
  }

  async getDashboardStats() {
    return this.request('/dashboard/stats');
  }

  async explainScan(scanId) {
    return this.request(`/ai/explain-scan/${scanId}`, { method: 'POST' });
  }

  async explainFinding(findingId) {
    return this.request(`/ai/explain-finding/${findingId}`, { method: 'POST' });
  }

  async askRAG(question, scanJobId = null) {
    return this.request('/ai/rag/ask', {
      method: 'POST',
      body: JSON.stringify({ question, scan_job_id: scanJobId }),
    });
  }

  async generateReport(scanId, format = 'html') {
    return this.request(`/reports/generate/${scanId}?format=${encodeURIComponent(format)}`, {
      method: 'POST',
    });
  }

  getReportUrl(scanId) {
    return `${API_BASE_URL}/reports/scan/${scanId}/view`;
  }

  async fetchReportHtml(scanId) {
    const token = this.getToken();
    const response = await fetch(this.getReportUrl(scanId), {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });

    if (response.status === 401) {
      this.setToken(null);
      window.dispatchEvent(new Event('auth:unauthorized'));
    }

    if (!response.ok) {
      let message = 'Failed to load report';
      try {
        const data = await response.json();
        message = formatApiDetail(data?.detail, message);
      } catch {
        // Non-JSON error body
      }
      throw new Error(message);
    }

    return response.text();
  }

  async openReport(scanId) {
    await this.generateReport(scanId, 'html').catch(() => null);
    const html = await this.fetchReportHtml(scanId);
    const blob = new Blob([html], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const opened = window.open(url, '_blank', 'noopener,noreferrer');
    if (!opened) {
      URL.revokeObjectURL(url);
      throw new Error('Pop-up blocked. Allow pop-ups to view the report.');
    }
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }

  async downloadScanPdf(scanId) {
    await this.generateReport(scanId, 'pdf').catch(() => null);
    await this.requestBlob(`/reports/scan/${scanId}/pdf`, `cybersentinel-scan-${scanId}.pdf`);
  }
}

export const api = new ApiService();
