import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { ScoreGauge } from '../components/ScoreGauge';
import { RiskBadge } from '../components/RiskBadge';
import { EmptyState } from '../components/EmptyState';
import { SkeletonLoader } from '../components/SkeletonLoader';
import { StatusBanner } from '../components/StatusBanner';
import { formatScore, formatShortDate, formatDate, isActiveScan, notifyScanUpdated } from '../utils/format';
import { domainValidationMessage, sanitizeDomain } from '../utils/domain';
import {
  Plus, Globe, FileText, Trash2, ArrowRight, ShieldCheck, ShieldAlert,
  Activity, ExternalLink, RefreshCw, Sparkles, Layers
} from 'lucide-react';

export const DashboardPage = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [quickDomain, setQuickDomain] = useState('');
  const [quickLoading, setQuickLoading] = useState(false);
  const [quickAuthorized, setQuickAuthorized] = useState(false);
  const [error, setError] = useState('');
  const [loadError, setLoadError] = useState('');
  const [success, setSuccess] = useState('');

  const navigate = useNavigate();

  const fetchStats = async ({ silent = false } = {}) => {
    try {
      if (!silent) setLoading(true);
      const data = await api.getDashboardStats();
      setStats(data);
      setLoadError('');
    } catch (err) {
      setLoadError(err.message || 'Failed to load dashboard metrics');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    const onUpdated = () => fetchStats({ silent: true });
    window.addEventListener('scan:updated', onUpdated);
    return () => window.removeEventListener('scan:updated', onUpdated);
  }, []);

  useEffect(() => {
    const active = (stats?.recent_scans || []).some((s) => isActiveScan(s.status));
    if (!active) return undefined;
    const interval = setInterval(() => fetchStats({ silent: true }), 2500);
    return () => clearInterval(interval);
  }, [stats]);

  const handleQuickScan = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    if (!quickAuthorized) {
      setError('Please confirm you are authorized to assess this domain before launching a scan.');
      return;
    }
    const clean = sanitizeDomain(quickDomain);
    const formatError = domainValidationMessage(clean);
    if (formatError) {
      setError(formatError);
      return;
    }

    setQuickLoading(true);
    try {
      const preflight = await api.validateDomain(clean, true);
      if (!preflight.valid) {
        setError(preflight.message || 'Domain failed validation');
        setQuickLoading(false);
        return;
      }
      const scanJob = await api.startScan(preflight.domain || clean, null, quickAuthorized);
      notifyScanUpdated(scanJob.id);
      setSuccess(`Scan job #${scanJob.id} launched successfully. Directing to live diagnostics…`);
      navigate(`/scan/${scanJob.id}`);
    } catch (err) {
      setError(err.message || 'Failed to launch quick scan');
      setQuickLoading(false);
    }
  };

  const handleDeleteScan = async (id, domain) => {
    if (!window.confirm(`Delete assessment record #${id} for ${domain}?`)) return;
    try {
      await api.deleteScan(id);
      setSuccess(`Deleted assessment for ${domain}. Metrics updated.`);
      fetchStats({ silent: true });
    } catch (err) {
      setError(err.message || 'Delete failed');
    }
  };

  if (loading) {
    return (
      <div className="layout-container" style={{ padding: '40px 24px' }}>
        <div style={{ marginBottom: '32px' }}>
          <div className="skeleton-shimmer" style={{ width: '300px', height: '32px', marginBottom: '8px' }} />
          <div className="skeleton-shimmer" style={{ width: '450px', height: '16px' }} />
        </div>
        <div className="grid-cols-3" style={{ marginBottom: '32px' }}>
          <SkeletonLoader type="stats" count={3} />
        </div>
        <SkeletonLoader type="table" count={1} />
      </div>
    );
  }

  const trend = stats?.score_trend || [];
  const maxTrend = Math.max(...trend.map((t) => Number(t.score) || 0), 100);

  return (
    <div className="layout-container" style={{ padding: '40px 24px' }}>
      {/* Top Banner & Quick Audit Bar */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          marginBottom: '32px',
          flexWrap: 'wrap',
          gap: '24px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h1 style={{ fontSize: '28px', fontWeight: 800, color: 'var(--text-white)' }}>
              Security Posture Command Center
            </h1>
            <span
              style={{
                fontSize: '11px',
                background: 'rgba(16, 185, 129, 0.12)',
                color: 'var(--color-minimal)',
                padding: '3px 8px',
                borderRadius: '9999px',
                fontWeight: 700,
                border: '1px solid rgba(16, 185, 129, 0.25)',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '5px',
              }}
            >
              <Activity size={12} /> Live Engine
            </span>
          </div>
          <p style={{ color: 'var(--text-muted)', fontSize: '14px', marginTop: '6px' }}>
            Aggregated diagnostics and real-time posture ratings from verified perimeter scans.
          </p>
        </div>

        {/* Quick Audit Form */}
        <div
          className="glass-panel"
          style={{
            padding: '16px 20px',
            maxWidth: '440px',
            flex: '1 1 340px',
            minWidth: 0,
            boxShadow: 'var(--shadow-sm)',
          }}
        >
          <div style={{ fontSize: '12px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '10px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Sparkles size={13} color="var(--accent-blue)" /> Quick Perimeter Scan
          </div>

          <form onSubmit={handleQuickScan}>
            <div style={{ display: 'flex', gap: '8px', marginBottom: '10px' }}>
              <div style={{ position: 'relative', flex: 1 }}>
                <input
                  type="text"
                  className="input-field"
                  placeholder="Target domain (e.g. acme.com)..."
                  value={quickDomain}
                  onChange={(e) => setQuickDomain(e.target.value)}
                  style={{ paddingLeft: '36px', height: '40px', fontSize: '13px' }}
                  aria-label="Target domain for quick scan"
                />
                <Globe size={15} color="var(--text-muted)" style={{ position: 'absolute', left: '12px', top: '13px' }} />
              </div>
              <button
                type="submit"
                disabled={quickLoading || !quickDomain.trim() || !quickAuthorized}
                className="btn btn-primary"
                style={{ height: '40px', padding: '0 16px', fontSize: '13px' }}
              >
                <Plus size={15} /> {quickLoading ? 'Validating…' : 'Scan'}
              </button>
            </div>

            <label
              htmlFor="quick-scan-authorization"
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '8px',
                fontSize: '11.5px',
                color: 'var(--text-dim)',
                cursor: 'pointer',
                lineHeight: 1.4,
              }}
            >
              <input
                id="quick-scan-authorization"
                type="checkbox"
                checked={quickAuthorized}
                onChange={(e) => setQuickAuthorized(e.target.checked)}
                style={{ marginTop: '2px', accentColor: 'var(--accent-blue)' }}
              />
              <span>
                I confirm I am authorized to assess this domain. (Recorded in audit logs)
              </span>
            </label>
          </form>
        </div>
      </div>

      {loadError && <StatusBanner type="error">{loadError}</StatusBanner>}
      {error && <StatusBanner type="error">{error}</StatusBanner>}
      {success && <StatusBanner type="success">{success}</StatusBanner>}

      {/* 3 Metric Cards Grid */}
      <div className="grid-cols-3" style={{ marginBottom: '32px' }}>
        {/* Metric 1: Average Score Gauge */}
        <div className="glass-panel" style={{ display: 'flex', alignItems: 'center', gap: '22px', padding: '24px' }}>
          <ScoreGauge score={stats?.average_score ?? 0} size={110} showGrade={stats?.average_score != null} />
          <div>
            <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              AVERAGE POSTURE SCORE
            </div>
            <div style={{ fontSize: '24px', fontWeight: 900, color: 'var(--text-white)', marginTop: '4px', fontFamily: 'var(--font-display)' }}>
              {stats?.average_score != null ? formatScore(stats.average_score) : 'No completed audits'}
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Computed across {stats?.domains_scanned || 0} unique domain targets
            </p>
          </div>
        </div>

        {/* Metric 2: Open Findings Breakdown */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', padding: '24px' }}>
          <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '12px' }}>
            OPEN FINDINGS SEVERITY MATRIX
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '8px' }}>
            <div style={{ background: 'var(--color-critical-bg)', padding: '10px 6px', borderRadius: '8px', border: '1px solid var(--color-critical-border)', textAlign: 'center' }}>
              <div style={{ fontSize: '18px', fontWeight: 800, color: '#fb7185' }}>{stats?.critical_findings || 0}</div>
              <div style={{ fontSize: '10px', color: '#fb7185', textTransform: 'uppercase', fontWeight: 700, marginTop: '2px' }}>Critical</div>
            </div>
            <div style={{ background: 'var(--color-high-bg)', padding: '10px 6px', borderRadius: '8px', border: '1px solid var(--color-high-border)', textAlign: 'center' }}>
              <div style={{ fontSize: '18px', fontWeight: 800, color: '#fb923c' }}>{stats?.high_findings || 0}</div>
              <div style={{ fontSize: '10px', color: '#fb923c', textTransform: 'uppercase', fontWeight: 700, marginTop: '2px' }}>High</div>
            </div>
            <div style={{ background: 'var(--color-medium-bg)', padding: '10px 6px', borderRadius: '8px', border: '1px solid var(--color-medium-border)', textAlign: 'center' }}>
              <div style={{ fontSize: '18px', fontWeight: 800, color: '#fbbf24' }}>{stats?.medium_findings || 0}</div>
              <div style={{ fontSize: '10px', color: '#fbbf24', textTransform: 'uppercase', fontWeight: 700, marginTop: '2px' }}>Medium</div>
            </div>
            <div style={{ background: 'var(--color-low-bg)', padding: '10px 6px', borderRadius: '8px', border: '1px solid var(--color-low-border)', textAlign: 'center' }}>
              <div style={{ fontSize: '18px', fontWeight: 800, color: '#60a5fa' }}>{stats?.low_findings || 0}</div>
              <div style={{ fontSize: '10px', color: '#60a5fa', textTransform: 'uppercase', fontWeight: 700, marginTop: '2px' }}>Low</div>
            </div>
          </div>
        </div>

        {/* Metric 3: Audit Inventory */}
        <div className="glass-panel" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', padding: '24px' }}>
          <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '6px' }}>
            ASSESSMENT LOG INVENTORY
          </div>
          <div style={{ fontSize: '32px', fontWeight: 900, color: 'var(--accent-blue)', fontFamily: 'var(--font-display)', lineHeight: 1.1 }}>
            {stats?.total_scans || 0}
          </div>
          <p style={{ fontSize: '12.5px', color: 'var(--text-muted)', marginTop: '6px' }}>
            {stats?.completed_scans || 0} completed audits ready for executive export
          </p>
        </div>
      </div>

      {/* Score Trend Visualization */}
      {trend.length > 0 && (
        <div className="glass-panel" style={{ padding: '24px', marginBottom: '32px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-white)' }}>
              Historical Security Score Progression
            </h3>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Latest {trend.length} completed assessments</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'flex-end', gap: '12px', height: '140px', padding: '10px 0', borderBottom: '1px solid var(--border-subtle)' }}>
            {trend.map((point, idx) => {
              const scoreVal = Number(point.score) || 0;
              const heightPct = Math.max(12, (scoreVal / maxTrend) * 100);
              return (
                <div key={`${point.domain}-${idx}`} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', height: '100%', justifyContent: 'flex-end' }}>
                  <div
                    title={`${point.domain}: ${formatScore(point.score)}`}
                    style={{
                      width: '100%',
                      maxWidth: '36px',
                      height: `${heightPct}%`,
                      background: scoreVal >= 80 ? 'linear-gradient(180deg, #10b981, #06b6d4)' : scoreVal >= 60 ? 'linear-gradient(180deg, #38bdf8, #6366f1)' : 'linear-gradient(180deg, #f59e0b, #f43f5e)',
                      borderRadius: '6px 6px 0 0',
                      transition: 'height 0.4s ease',
                      boxShadow: '0 0 10px rgba(56, 189, 248, 0.2)',
                    }}
                  />
                  <div style={{ fontSize: '10.5px', color: 'var(--text-dim)', marginTop: '8px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: '60px' }}>
                    {formatShortDate(point.date)}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Recent Domain Assessments Table */}
      <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '20px 24px', borderBottom: '1px solid var(--border-subtle)', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h3 style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-white)' }}>Recent Domain Assessments</h3>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Latest scans from your verified account</span>
          </div>
          <Link to="/history" className="btn btn-secondary" style={{ fontSize: '12.5px', padding: '7px 14px' }}>
            View Full History <ArrowRight size={14} />
          </Link>
        </div>

        {stats?.recent_scans?.length > 0 ? (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13.5px' }}>
              <thead>
                <tr style={{ background: 'rgba(255, 255, 255, 0.015)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-dim)' }}>
                  <th style={{ padding: '14px 24px', fontWeight: 600 }}>Target Domain</th>
                  <th style={{ padding: '14px 20px', fontWeight: 600 }}>Status</th>
                  <th style={{ padding: '14px 20px', fontWeight: 600 }}>Score</th>
                  <th style={{ padding: '14px 20px', fontWeight: 600 }}>Risk Posture</th>
                  <th style={{ padding: '14px 20px', fontWeight: 600 }}>Audit Date</th>
                  <th style={{ padding: '14px 24px', textAlign: 'right', fontWeight: 600 }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {stats.recent_scans.map((scan) => {
                  const running = isActiveScan(scan.status);
                  return (
                    <tr key={scan.id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                      <td style={{ padding: '16px 24px', fontWeight: 600 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                          <Globe size={16} color="var(--accent-blue)" />
                          <Link to={`/scan/${scan.id}`} style={{ color: 'var(--text-white)', textDecoration: 'none' }}>
                            {scan.target_domain}
                          </Link>
                        </div>
                      </td>
                      <td style={{ padding: '16px 20px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                          {running && <span className="animate-pulse-glow" style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--accent-cyan)' }} />}
                          <span
                            style={{
                              textTransform: 'uppercase',
                              fontSize: '11px',
                              fontWeight: 700,
                              color: scan.status === 'completed' ? 'var(--color-minimal)' : scan.status === 'failed' ? 'var(--color-critical)' : 'var(--accent-cyan)',
                            }}
                          >
                            {scan.status}
                          </span>
                        </div>
                      </td>
                      <td style={{ padding: '16px 20px', fontWeight: 800, color: 'var(--accent-blue)', fontFamily: 'var(--font-display)' }}>
                        {formatScore(scan.overall_score)}
                      </td>
                      <td style={{ padding: '16px 20px' }}>
                        <RiskBadge level={scan.risk_level || 'info'} size="sm" />
                      </td>
                      <td style={{ padding: '16px 20px', color: 'var(--text-muted)', fontSize: '13px' }}>
                        {formatDate(scan.created_at)}
                      </td>
                      <td style={{ padding: '16px 24px', textAlign: 'right' }}>
                        <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
                          <Link to={`/scan/${scan.id}`} className="btn btn-secondary" style={{ padding: '6px 12px', fontSize: '12px' }}>
                            {running ? 'Watch' : 'View'}
                          </Link>
                          {scan.status === 'completed' && (
                            <button
                              type="button"
                              className="btn btn-secondary"
                              style={{ padding: '6px 10px', fontSize: '12px' }}
                              title="View Formal Report"
                              onClick={async () => {
                                try {
                                  await api.openReport(scan.id);
                                } catch (err) {
                                  setError(err.message || 'Failed to open report');
                                }
                              }}
                            >
                              <FileText size={14} />
                            </button>
                          )}
                          <button
                            type="button"
                            onClick={() => handleDeleteScan(scan.id, scan.target_domain)}
                            className="btn btn-danger"
                            style={{ padding: '6px 10px', fontSize: '12px' }}
                            title="Delete Assessment Record"
                          >
                            <Trash2 size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState
            title="No Scans Performed Yet"
            description="Run your first perimeter security audit to populate posture ratings, finding breakdown, and trends."
            actionLabel="Launch First Audit"
            actionTo="/scan/new"
          />
        )}
      </div>
    </div>
  );
};
