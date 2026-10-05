import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { api } from '../services/api';
import { RiskBadge } from '../components/RiskBadge';
import { EmptyState } from '../components/EmptyState';
import { SkeletonLoader } from '../components/SkeletonLoader';
import { StatusBanner } from '../components/StatusBanner';
import { formatDate, formatScore, isActiveScan } from '../utils/format';
import { Globe, FileText, Trash2, Search, Plus, ExternalLink, ChevronLeft, ChevronRight, Activity } from 'lucide-react';

export const HistoryPage = () => {
  const [scans, setScans] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [riskFilter, setRiskFilter] = useState('all');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const pageSize = 20;

  const fetchScans = async ({ silent = false } = {}) => {
    try {
      if (!silent) setLoading(true);
      const data = await api.getScans(page, pageSize);
      setScans(data.scans || []);
      setTotal(data.total || 0);
      setError('');
    } catch (err) {
      setError(err.message || 'Failed to fetch scan history');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchScans();
    const onUpdated = () => fetchScans({ silent: true });
    window.addEventListener('scan:updated', onUpdated);
    return () => window.removeEventListener('scan:updated', onUpdated);
  }, [page]);

  useEffect(() => {
    const active = scans.some((s) => isActiveScan(s.status));
    if (!active) return undefined;
    const interval = setInterval(() => fetchScans({ silent: true }), 2500);
    return () => clearInterval(interval);
  }, [scans]);

  const handleDelete = async (id, domain) => {
    if (!window.confirm(`Are you sure you want to delete scan #${id} for ${domain}?`)) {
      return;
    }
    try {
      await api.deleteScan(id);
      setSuccess(`Deleted assessment #${id} for ${domain}.`);
      fetchScans({ silent: true });
    } catch (err) {
      setError(err.message || 'Failed to delete scan');
    }
  };

  const filteredScans = scans.filter((s) => {
    const matchesSearch = s.target_domain.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesRisk = riskFilter === 'all' || (s.risk_level && s.risk_level.toLowerCase() === riskFilter.toLowerCase());
    return matchesSearch && matchesRisk;
  });

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="layout-container" style={{ padding: '40px 24px' }}>
      {/* Top Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <h1 style={{ fontSize: '28px', fontWeight: 800, color: 'var(--text-white)' }}>
            Assessment Logs & History
          </h1>
          <p style={{ color: 'var(--text-muted)', fontSize: '14px', marginTop: '4px' }}>
            Historical audit logs from verified perimeter scans with instant report viewing and export.
          </p>
        </div>
        <Link to="/scan/new" className="btn btn-primary">
          <Plus size={16} /> New Assessment
        </Link>
      </div>

      {error && <StatusBanner type="error">{error}</StatusBanner>}
      {success && <StatusBanner type="success">{success}</StatusBanner>}

      {/* Filter and Search Bar */}
      <div
        className="glass-panel"
        style={{
          padding: '16px 20px',
          marginBottom: '24px',
          display: 'flex',
          gap: '16px',
          alignItems: 'center',
          flexWrap: 'wrap',
          justifyContent: 'space-between',
        }}
      >
        <div style={{ position: 'relative', flex: 1, minWidth: '260px' }}>
          <input
            type="text"
            className="input-field"
            style={{ paddingLeft: '38px', height: '40px', fontSize: '13.5px' }}
            placeholder="Search logs by domain (e.g. company.com)..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            aria-label="Search scan history by domain"
          />
          <Search size={16} color="var(--text-muted)" style={{ position: 'absolute', left: '12px', top: '13px' }} />
        </div>

        <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '12px', color: 'var(--text-dim)', fontWeight: 600, marginRight: '4px' }}>Filter Risk:</span>
          {['all', 'critical', 'high', 'medium', 'low', 'minimal'].map((lvl) => (
            <button
              key={lvl}
              type="button"
              onClick={() => setRiskFilter(lvl)}
              className={`btn ${riskFilter === lvl ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '11.5px', padding: '5px 12px', textTransform: 'capitalize' }}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* Scan History Table Card */}
      <div className="glass-panel" style={{ padding: '0', overflow: 'hidden' }}>
        {loading ? (
          <SkeletonLoader type="table" count={1} />
        ) : filteredScans.length > 0 ? (
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '13.5px' }}>
              <thead>
                <tr style={{ background: 'rgba(255, 255, 255, 0.015)', borderBottom: '1px solid var(--border-subtle)', color: 'var(--text-dim)' }}>
                  <th style={{ padding: '14px 24px', fontWeight: 600 }}>Target Domain</th>
                  <th style={{ padding: '14px 20px', fontWeight: 600 }}>Status</th>
                  <th style={{ padding: '14px 20px', fontWeight: 600 }}>Security Score</th>
                  <th style={{ padding: '14px 20px', fontWeight: 600 }}>Risk Posture</th>
                  <th style={{ padding: '14px 20px', fontWeight: 600 }}>Audit Date</th>
                  <th style={{ padding: '14px 24px', textAlign: 'right', fontWeight: 600 }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredScans.map((scan) => {
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
                              title="View Assessment Report"
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
                            onClick={() => handleDelete(scan.id, scan.target_domain)}
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
            title={error ? 'Could Not Load Scan Logs' : 'No Matching Scan Logs'}
            description={error || 'No assessment logs found matching your search term or risk filter.'}
            actionLabel="Launch New Scan"
            actionTo="/scan/new"
          />
        )}
      </div>

      {/* Pagination Controls */}
      {total > pageSize && (
        <div style={{ display: 'flex', justifyContent: 'center', gap: '12px', marginTop: '24px', alignItems: 'center' }}>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={page <= 1}
            onClick={() => setPage((p) => p - 1)}
            style={{ padding: '8px 14px' }}
          >
            <ChevronLeft size={16} /> Previous
          </button>
          <span style={{ fontSize: '13px', color: 'var(--text-muted)' }}>
            Page <strong>{page}</strong> of <strong>{totalPages}</strong> ({total} total audits)
          </span>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => p + 1)}
            style={{ padding: '8px 14px' }}
          >
            Next <ChevronRight size={16} />
          </button>
        </div>
      )}
    </div>
  );
};
