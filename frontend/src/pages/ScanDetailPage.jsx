import React, { useEffect, useRef, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../services/api';
import { ScoreGauge } from '../components/ScoreGauge';
import { RiskBadge } from '../components/RiskBadge';
import { FindingCard } from '../components/FindingCard';
import { ModuleCard } from '../components/ModuleCard';
import { ScanProgress } from '../components/ScanProgress';
import { SkeletonLoader } from '../components/SkeletonLoader';
import { StatusBanner } from '../components/StatusBanner';
import { formatDate, formatScore, isActiveScan, notifyScanUpdated } from '../utils/format';
import {
  Shield, FileText, AlertTriangle, CheckCircle2, ArrowLeft,
  RefreshCw, ExternalLink, Sparkles, Download, Layers, TrendingUp, TrendingDown,
  Info, ShieldAlert, Cpu
} from 'lucide-react';

export const ScanDetailPage = () => {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [polling, setPolling] = useState(false);
  const [reportError, setReportError] = useState('');
  const [reportBusy, setReportBusy] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [recommendations, setRecommendations] = useState(null);
  const [compare, setCompare] = useState(null);
  const [justCompleted, setJustCompleted] = useState(false);
  const wasActive = useRef(false);

  const fetchScan = async () => {
    try {
      const data = await api.getScanDetail(id);
      setScan(data);
      const active = isActiveScan(data.status);
      setPolling(active);
      if (active) wasActive.current = true;
      if (!active && wasActive.current && data.status === 'completed') {
        setJustCompleted(true);
        notifyScanUpdated(data.id);
      }
      if (data.status === 'failed') {
        notifyScanUpdated(data.id);
      }
      if (data.status === 'completed') {
        if (Array.isArray(data.recommendations) && data.recommendations.length) {
          setRecommendations({
            summary: data.ai_explanation?.summary,
            recommendations: data.recommendations,
          });
        } else {
          try {
            const recs = await api.getRecommendations(id);
            setRecommendations(recs);
          } catch {
            setRecommendations(null);
          }
        }
        try {
          const history = await api.getDomainHistory(data.target_domain, 5);
          const others = (history.scans || []).filter((s) => s.id !== data.id && s.status === 'completed');
          if (others.length) {
            const cmp = await api.compareScans(others[0].id, data.id);
            setCompare(cmp);
          } else {
            setCompare(null);
          }
        } catch {
          setCompare(null);
        }
      }
    } catch (err) {
      setError(err.message || 'Failed to load scan details');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setLoading(true);
    setError('');
    setJustCompleted(false);
    setRecommendations(null);
    setCompare(null);
    fetchScan();
  }, [id]);

  useEffect(() => {
    let interval = null;
    if (polling) {
      interval = setInterval(async () => {
        try {
          const statusData = await api.getScanStatus(id);
          if (statusData.status === 'completed' || statusData.status === 'failed') {
            setPolling(false);
            fetchScan();
          } else {
            setScan((prev) => (prev ? { ...prev, ...statusData } : prev));
          }
        } catch (err) {
          setError(err.message || 'Lost connection while polling scan status');
        }
      }, 2000);
    }
    return () => clearInterval(interval);
  }, [polling, id]);

  const handleOpenReport = async () => {
    setReportBusy('html');
    setReportError('');
    try {
      await api.openReport(scan.id);
    } catch (err) {
      setReportError(err.message || 'Failed to open report');
    } finally {
      setReportBusy('');
    }
  };

  const handleDownloadPdf = async () => {
    setReportBusy('pdf');
    setReportError('');
    try {
      await api.downloadScanPdf(scan.id);
    } catch (err) {
      setReportError(err.message || 'Failed to download PDF');
    } finally {
      setReportBusy('');
    }
  };

  if (loading) {
    return (
      <div className="layout-container" style={{ padding: '40px 24px' }}>
        <div className="skeleton-shimmer" style={{ width: '250px', height: '30px', marginBottom: '24px' }} />
        <div className="glass-panel" style={{ padding: '32px', marginBottom: '32px' }}>
          <SkeletonLoader type="stats" count={1} />
        </div>
        <SkeletonLoader type="card" count={3} />
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="layout-container" style={{ padding: '60px 24px', textAlign: 'center' }}>
        <div className="glass-panel" style={{ padding: '48px 24px', maxWidth: '520px', margin: '0 auto' }}>
          <ShieldAlert size={40} color="var(--color-critical)" style={{ margin: '0 auto 16px' }} />
          <h2 style={{ fontSize: '20px', marginBottom: '8px' }}>Scan Record Not Available</h2>
          <p style={{ color: 'var(--text-muted)', marginBottom: '24px', fontSize: '14px' }}>
            {error || 'The requested scan record could not be found or you may lack permission to access it.'}
          </p>
          <Link to="/dashboard" className="btn btn-primary">
            <ArrowLeft size={16} /> Return to Command Center
          </Link>
        </div>
      </div>
    );
  }

  if (isActiveScan(scan.status)) {
    return (
      <div className="layout-container" style={{ padding: '40px 24px' }}>
        <ScanProgress scanStatus={scan} />
      </div>
    );
  }

  if (scan.status === 'failed') {
    return (
      <div className="layout-container" style={{ padding: '40px 24px', maxWidth: '640px' }}>
        <StatusBanner type="error">
          Scan failed: {scan.error_message || 'The backend scanners could not complete this job.'}
        </StatusBanner>
        <div className="glass-panel" style={{ padding: '36px', textAlign: 'center' }}>
          <AlertTriangle size={36} color="var(--color-critical)" style={{ margin: '0 auto 12px' }} />
          <h2 style={{ marginBottom: '6px', fontSize: '22px' }}>{scan.target_domain}</h2>
          <p style={{ color: 'var(--text-muted)', marginBottom: '24px', fontSize: '13.5px' }}>Assessment job #{scan.id} failed during execution.</p>
          <div style={{ display: 'flex', gap: '12px', justifyContent: 'center' }}>
            <Link to={`/scan/new?domain=${encodeURIComponent(scan.target_domain)}`} className="btn btn-primary">
              <RefreshCw size={15} /> Retry Scan
            </Link>
            <Link to="/dashboard" className="btn btn-secondary">
              Back to Dashboard
            </Link>
          </div>
        </div>
      </div>
    );
  }

  const moduleGroups = {};
  (scan.results || []).forEach((r) => {
    if (!moduleGroups[r.module_name]) {
      moduleGroups[r.module_name] = [];
    }
    moduleGroups[r.module_name].push(r);
  });

  const filteredFindings = (scan.findings || []).filter((f) => {
    if (severityFilter === 'all') return true;
    return (f.severity || '').toLowerCase() === severityFilter.toLowerCase();
  });

  const moduleScores = scan.score_breakdown?.module_scores || {};

  return (
    <div className="layout-container" style={{ padding: '40px 24px' }}>
      {justCompleted && (
        <StatusBanner type="success">
          Perimeter diagnostic scan completed! Deterministic posture score {formatScore(scan.overall_score)} has been stored.
        </StatusBanner>
      )}
      {reportError && <StatusBanner type="error">{reportError}</StatusBanner>}

      {/* Top Header Bar */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '28px',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <Link to="/history" className="btn btn-secondary" style={{ padding: '8px 12px' }} title="Back to Scan History">
            <ArrowLeft size={16} />
          </Link>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <h1 style={{ fontSize: '26px', fontWeight: 800, color: 'var(--text-white)' }}>{scan.target_domain}</h1>
              <RiskBadge level={scan.risk_level || 'minimal'} size="md" />
            </div>
            <span style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
              Scan ID #{scan.id} • Completed {formatDate(scan.completed_at)}
            </span>
          </div>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!!reportBusy}
            onClick={handleOpenReport}
            title="View full HTML security report"
          >
            <FileText size={15} /> {reportBusy === 'html' ? 'Opening Report…' : 'View HTML Report'} <ExternalLink size={13} />
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={!!reportBusy}
            onClick={handleDownloadPdf}
            title="Download executive PDF assessment report"
          >
            <Download size={15} /> {reportBusy === 'pdf' ? 'Generating PDF…' : 'Download PDF'}
          </button>
          <Link to={`/scan/new?domain=${encodeURIComponent(scan.target_domain)}`} className="btn btn-primary">
            <RefreshCw size={15} /> Re-Scan Domain
          </Link>
        </div>
      </div>

      {/* Score Summary Showcase Card */}
      <div
        className="glass-panel score-summary-card"
        style={{
          display: 'grid',
          gridTemplateColumns: 'auto 1fr',
          gap: '36px',
          alignItems: 'center',
          padding: '36px',
          marginBottom: '32px',
        }}
      >
        <ScoreGauge score={scan.overall_score ?? 0} size={150} />

        <div>
          <div style={{ fontSize: '11.5px', fontWeight: 700, color: 'var(--text-dim)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '4px' }}>
            DETERMINISTIC PERIMETER RATING
          </div>
          <h2 style={{ fontSize: '22px', fontWeight: 800, color: 'var(--text-white)', marginBottom: '8px' }}>
            Overall Security Posture Assessment
          </h2>
          <p style={{ fontSize: '14px', color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: '20px' }}>
            Calculated score {formatScore(scan.overall_score)}
            {scan.score_breakdown?.percentage != null ? ` (${scan.score_breakdown.percentage}%)` : ''} derived from 6 independent diagnostic vectors across public TLS, HTTPS redirection, OWASP security headers, DNS integrity, email anti-spoofing, and open network ports.
          </p>

          <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap', fontSize: '13.5px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-minimal)', fontWeight: 600 }}>
              <CheckCircle2 size={17} /> <span>{scan.passed_count || 0} Checks Passed</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-medium)', fontWeight: 600 }}>
              <AlertTriangle size={17} /> <span>{scan.warning_count || 0} Warnings</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-critical)', fontWeight: 600 }}>
              <ShieldAlert size={17} /> <span>{scan.failed_count || 0} Issues Detected</span>
            </div>
          </div>
        </div>
      </div>

      {/* Comparison against previous scan */}
      {compare && (
        <div
          className="glass-panel"
          style={{
            padding: '20px 24px',
            marginBottom: '28px',
            borderLeft: '4px solid var(--accent-cyan)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '12px',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '14px', fontWeight: 700, color: 'var(--text-white)' }}>
              <TrendingUp size={16} color="var(--accent-cyan)" />
              <span>Comparative Delta vs Previous Scan #{compare.scan_a.id}</span>
            </div>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Score delta:{' '}
              <strong style={{ color: compare.score_delta > 0 ? 'var(--color-minimal)' : compare.score_delta < 0 ? 'var(--color-critical)' : 'var(--text-white)' }}>
                {compare.score_delta == null ? '—' : `${compare.score_delta > 0 ? '+' : ''}${Number(compare.score_delta).toFixed(1)} pts`}
              </strong>
              {' '}• Findings added: <strong>{compare.findings_added?.length || 0}</strong>
              {' '}• Findings resolved: <strong style={{ color: 'var(--color-minimal)' }}>{compare.findings_resolved?.length || 0}</strong>
            </p>
          </div>
        </div>
      )}

      {/* AI Executive Briefing / Grounded Guidance */}
      <div
        className="glass-panel"
        style={{
          marginBottom: '32px',
          borderLeft: '4px solid var(--accent-violet)',
          padding: '26px 30px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent-violet)', fontWeight: 700, fontSize: '15px' }}>
            <Sparkles size={18} />
            <span>{scan.ai_explanation?.available ? 'AI Executive Intelligence Briefing' : 'Security Posture Briefing'}</span>
          </div>
        </div>

        {scan.ai_explanation?.available === false && (
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '10px' }}>
            {scan.ai_explanation?.summary || 'AI explanation is temporarily unavailable.'} Rule-based diagnostic recommendations are listed below.
          </p>
        )}
        {(scan.ai_explanation?.available && scan.ai_explanation?.summary) || scan.ai_summary ? (
          <div style={{ fontSize: '14px', lineHeight: 1.7, color: 'var(--text-main)', whiteSpace: 'pre-line' }}>
            {scan.ai_explanation?.available ? scan.ai_explanation.summary : scan.ai_summary}
          </div>
        ) : null}
        {Array.isArray(scan.ai_explanation?.details) && scan.ai_explanation.details.length > 0 && (
          <div style={{ marginTop: '18px' }}>
            {scan.ai_explanation.details.map((detail) => (
              <div key={detail.title} style={{ paddingTop: '14px', marginTop: '14px', borderTop: '1px solid var(--border-subtle)' }}>
                <strong style={{ fontSize: '14px', color: 'var(--text-white)' }}>{detail.title}</strong>
                {detail.explanation && (
                  <p style={{ fontSize: '13.5px', color: 'var(--text-main)', marginTop: '4px', lineHeight: 1.6 }}>{detail.explanation}</p>
                )}
                {detail.why_it_matters && (
                  <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '6px' }}>
                    <strong>Why it matters:</strong> {detail.why_it_matters}
                  </p>
                )}
                {detail.impact && (
                  <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '4px' }}>
                    <strong>Business Impact:</strong> {detail.impact}
                  </p>
                )}
                {Array.isArray(detail.remediation) && detail.remediation.length > 0 && (
                  <div style={{ marginTop: '8px' }}>
                    <strong style={{ fontSize: '12.5px', color: 'var(--accent-blue)' }}>Remediation Steps:</strong>
                    <ul style={{ marginTop: '4px', paddingLeft: '18px', fontSize: '13px', color: 'var(--text-main)', lineHeight: 1.6 }}>
                      {detail.remediation.map((step) => (
                        <li key={step}>{step}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Prioritized Remediation Plan */}
      {recommendations?.recommendations?.length > 0 && (
        <div className="glass-panel" style={{ padding: '24px 28px', marginBottom: '32px' }}>
          <h2 style={{ fontSize: '18px', fontWeight: 800, marginBottom: '6px' }}>Prioritized Remediation Action Plan</h2>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '18px' }}>{recommendations.summary}</p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {recommendations.recommendations.slice(0, 5).map((item) => (
              <div key={item.finding_id} style={{ padding: '12px 16px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginBottom: '6px' }}>
                  <RiskBadge level={item.severity} size="sm" />
                  <strong style={{ fontSize: '14px', color: 'var(--text-white)' }}>{item.title}</strong>
                </div>
                <p style={{ fontSize: '13px', color: 'var(--text-muted)', lineHeight: 1.5 }}>{item.recommendation}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Findings Section */}
      <div style={{ marginBottom: '36px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-white)' }}>
              Identified Security Findings ({filteredFindings.length})
            </h2>
            <span style={{ fontSize: '12.5px', color: 'var(--text-muted)' }}>
              Detailed vulnerability breakdowns with remediation steps, raw headers, and AI analysis
            </span>
          </div>

          {/* Severity Filter Tabs */}
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
            {['all', 'critical', 'high', 'medium', 'low'].map((level) => (
              <button
                key={level}
                onClick={() => setSeverityFilter(level)}
                className={`btn ${severityFilter === level ? 'btn-primary' : 'btn-ghost'}`}
                style={{ fontSize: '12px', padding: '5px 12px', textTransform: 'capitalize' }}
              >
                {level}
              </button>
            ))}
          </div>
        </div>

        {filteredFindings.length > 0 ? (
          filteredFindings.map((finding) => (
            <FindingCard
              key={finding.id}
              finding={finding}
              aiDetail={(scan.ai_explanation?.details || []).find(
                (detail) => (detail.title || '').toLowerCase() === (finding.title || '').toLowerCase()
              )}
            />
          ))
        ) : (
          <div className="glass-panel" style={{ textAlign: 'center', padding: '40px 24px', color: 'var(--color-minimal)' }}>
            <CheckCircle2 size={36} style={{ margin: '0 auto 12px' }} />
            <div style={{ fontWeight: 700, fontSize: '16px', color: 'var(--text-white)' }}>No Findings Matching Filter</div>
            <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginTop: '4px' }}>
              {(scan.findings || []).length === 0
                ? 'All diagnostic checks passed. No failed or warning findings recorded for this domain.'
                : 'No issues detected for the selected severity level.'}
            </p>
          </div>
        )}
      </div>

      {/* Module Verification Breakdown */}
      <div>
        <h2 style={{ fontSize: '20px', fontWeight: 800, color: 'var(--text-white)', marginBottom: '16px' }}>
          Diagnostic Module Breakdown
        </h2>
        {Object.keys(moduleGroups).length === 0 ? (
          <StatusBanner type="info">No module results were stored for this scan.</StatusBanner>
        ) : (
          <div className="grid-cols-2">
            {Object.entries(moduleGroups).map(([moduleName, results]) => (
              <ModuleCard
                key={moduleName}
                moduleName={moduleName}
                results={results}
                breakdown={moduleScores[moduleName]}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
