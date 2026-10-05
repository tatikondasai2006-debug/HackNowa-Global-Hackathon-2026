import React from 'react';
import { CheckCircle2, AlertTriangle, XCircle, ShieldCheck, Lock, Globe, Mail, Network, Info, Globe2 } from 'lucide-react';

const MODULE_ICONS = {
  tls: Lock,
  https: Globe2,
  headers: ShieldCheck,
  dns: Globe,
  email_security: Mail,
  ports: Network,
};

export const ModuleCard = ({ moduleName, results = [], breakdown }) => {
  const Icon = MODULE_ICONS[moduleName] || ShieldCheck;

  const passed = results.filter((r) => r.status === 'passed').length;
  const warnings = results.filter((r) => r.status === 'warning').length;
  const failed = results.filter((r) => r.status === 'failed' || r.status === 'error').length;
  const totalScoreEarned = breakdown?.earned ?? results.reduce((acc, r) => acc + (r.score_impact || 0), 0);
  const totalScoreMax = breakdown?.max ?? results.reduce((acc, r) => acc + (r.max_score || 0), 0);

  const displayTitles = {
    tls: 'TLS & SSL Configuration',
    https: 'HTTPS Availability',
    headers: 'HTTP Security Headers',
    dns: 'DNS & Domain Integrity',
    email_security: 'Email Spoofing Defenses',
    ports: 'Port & Attack Surface',
  };

  const pct = totalScoreMax > 0 ? Math.round((totalScoreEarned / totalScoreMax) * 100) : 100;

  return (
    <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div
            style={{
              background: 'rgba(56, 189, 248, 0.08)',
              border: '1px solid rgba(56, 189, 248, 0.25)',
              padding: '10px',
              borderRadius: '10px',
              color: 'var(--accent-blue)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Icon size={20} />
          </div>
          <div>
            <h4 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-white)' }}>
              {displayTitles[moduleName] || moduleName.toUpperCase()}
            </h4>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              {passed} passed • {warnings} warnings • {failed} failed
            </span>
          </div>
        </div>

        <div style={{ textAlign: 'right' }}>
          <div style={{ fontSize: '16px', fontWeight: 800, color: pct >= 80 ? 'var(--color-minimal)' : pct >= 50 ? 'var(--color-medium)' : 'var(--color-critical)' }}>
            {Number(totalScoreEarned).toFixed(0)} <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>/ {Number(totalScoreMax).toFixed(0)} pts</span>
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-dim)', fontWeight: 600 }}>{pct}% COMPLIANT</span>
        </div>
      </div>

      <div style={{ background: 'rgba(255, 255, 255, 0.05)', height: '6px', borderRadius: '9999px', overflow: 'hidden', marginBottom: '16px' }}>
        <div
          style={{
            width: `${pct}%`,
            height: '100%',
            background: pct >= 80 ? 'var(--color-minimal)' : pct >= 50 ? 'var(--color-medium)' : 'var(--color-critical)',
            borderRadius: '9999px',
            transition: 'width 0.6s ease',
          }}
        />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', flex: 1 }}>
        {results.map((check) => (
          <div
            key={check.id}
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '8px 10px',
              background: 'rgba(255, 255, 255, 0.02)',
              borderRadius: '6px',
              border: '1px solid var(--border-subtle)',
              fontSize: '13px',
              gap: '12px',
            }}
          >
            <span style={{ color: 'var(--text-main)', fontWeight: 500 }}>{check.title}</span>

            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', flexShrink: 0 }}>
              {check.status === 'passed' && (
                <span style={{ color: 'var(--color-minimal)', display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11.5px', fontWeight: 600 }}>
                  <CheckCircle2 size={13} /> Passed
                </span>
              )}
              {check.status === 'warning' && (
                <span style={{ color: 'var(--color-medium)', display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11.5px', fontWeight: 600 }}>
                  <AlertTriangle size={13} /> Warning
                </span>
              )}
              {(check.status === 'failed' || check.status === 'error') && (
                <span style={{ color: 'var(--color-critical)', display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11.5px', fontWeight: 600 }}>
                  <XCircle size={13} /> Issue
                </span>
              )}
              {check.status === 'info' && (
                <span style={{ color: 'var(--color-info)', display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11.5px', fontWeight: 600 }}>
                  <Info size={13} /> Info
                </span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
