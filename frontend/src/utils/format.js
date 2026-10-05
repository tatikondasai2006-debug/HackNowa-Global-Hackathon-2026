export function formatScore(score) {
  if (score === null || score === undefined || Number.isNaN(Number(score))) {
    return '—';
  }
  return `${Number(score).toFixed(1)} / 100`;
}

export function formatDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString();
}

export function formatShortDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleDateString();
}

export function isActiveScan(status) {
  return status === 'pending' || status === 'running';
}

export function notifyScanUpdated(scanId) {
  window.dispatchEvent(new CustomEvent('scan:updated', { detail: { scanId } }));
}
