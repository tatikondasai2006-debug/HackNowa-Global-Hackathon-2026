import React from 'react';
import { Shield, Radio, CheckCircle2, Loader2, Circle, AlertCircle } from 'lucide-react';

const MODULE_ORDER = [
  { key: 'tls', name: 'TLS & SSL' },
  { key: 'https', name: 'HTTPS' },
  { key: 'headers', name: 'HTTP Headers' },
  { key: 'dns', name: 'DNS & DNSSEC' },
  { key: 'email_security', name: 'SPF/DMARC' },
  { key: 'ports', name: 'Exposed Ports' },
];

export const ScanProgress = ({ scanStatus }) => {
  const {
    completed_checks = 0,
    total_checks = 0,
    current_module,
    status,
    target_domain,
  } = scanStatus || {};

  const progressPct = total_checks > 0
    ? Math.min(100, Math.round((completed_checks / total_checks) * 100))
    : (status === 'running' ? 8 : 2);

  const currentIndex = MODULE_ORDER.findIndex((m) => m.key === current_module);

  return (
    <div
      className="glass-panel"
      style={{
        textAlign: 'center',
        padding: '48px 32px',
        maxWidth: '780px',
        margin: '40px auto',
        position: 'relative',
        overflow: 'hidden',
        boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6), var(--shadow-glow-blue)',
      }}
    >
      {/* Radar Animation */}
      <div
        style={{
          width: '120px',
          height: '120px',
          borderRadius: '50%',
          border: '1px solid rgba(56, 189, 248, 0.25)',
          margin: '0 auto 28px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          position: 'relative',
          background: 'radial-gradient(circle, rgba(56, 189, 248, 0.12) 0%, transparent 70%)',
        }}
      >
        <div
          style={{
            position: 'absolute',
            width: '100%',
            height: '100%',
            borderRadius: '50%',
            borderTop: '2px solid var(--accent-blue)',
            animation: 'radarSweep 2s linear infinite',
          }}
        />
        <Shield size={44} color="var(--accent-blue)" style={{ zIndex: 2 }} />
      </div>

      <div
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '8px',
          padding: '4px 14px',
          background: 'rgba(56, 189, 248, 0.1)',
          border: '1px solid rgba(56, 189, 248, 0.25)',
          borderRadius: '9999px',
          color: 'var(--accent-blue)',
          fontSize: '12px',
          fontWeight: 700,
          marginBottom: '14px',
        }}
      >
        <Radio size={14} className="animate-pulse-glow" /> LIVE PROBE EXECUTION
      </div>

      <h2 style={{ fontSize: '26px', fontWeight: 800, marginBottom: '8px', color: 'var(--text-white)' }}>
        Auditing {target_domain || 'Target Perimeter'}
      </h2>
      <p style={{ fontSize: '14px', color: 'var(--text-muted)', maxWidth: '520px', margin: '0 auto 28px', lineHeight: 1.6 }}>
        Backend diagnostic modules are passively checking TLS trust, headers, DNSSEC, email security records, and open ports.
      </p>

      {/* Progress Bar */}
      <div style={{ background: 'rgba(255, 255, 255, 0.06)', borderRadius: '9999px', height: '10px', overflow: 'hidden', border: '1px solid var(--border-subtle)', marginBottom: '14px' }}>
        <div
          style={{
            width: `${progressPct}%`,
            height: '100%',
            background: 'linear-gradient(90deg, #0284c7, #8b5cf6, #38bdf8)',
            backgroundSize: '200% 100%',
            borderRadius: '9999px',
            transition: 'width 0.4s ease',
          }}
        />
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '13px', color: 'var(--text-muted)', marginBottom: '32px' }}>
        <span>
          Status: <strong style={{ color: 'var(--accent-cyan)' }}>{(status || 'pending').toUpperCase()}</strong>
          {current_module ? <> • Active: <strong style={{ color: 'var(--accent-cyan)' }}>{current_module.toUpperCase()}</strong></> : null}
        </span>
        <span style={{ fontWeight: 600 }}>{completed_checks} / {total_checks || '—'} Checks Completed ({progressPct}%)</span>
      </div>

      {/* Modules Status Grid */}
      <div className="grid-cols-6" style={{ borderTop: '1px solid var(--border-subtle)', paddingTop: '20px' }}>
        {MODULE_ORDER.map((m, idx) => {
          const isCurrent = current_module === m.key;
          const isDone = currentIndex === -1 ? completed_checks > 0 && idx < completed_checks : idx < currentIndex;
          return (
            <div
              key={m.key}
              style={{
                padding: '12px 8px',
                borderRadius: '8px',
                background: isCurrent ? 'rgba(56, 189, 248, 0.15)' : isDone ? 'rgba(16, 185, 129, 0.08)' : 'rgba(255, 255, 255, 0.02)',
                border: isCurrent ? '1px solid var(--accent-blue)' : isDone ? '1px solid rgba(16, 185, 129, 0.35)' : '1px solid var(--border-subtle)',
                fontSize: '11.5px',
                fontWeight: 600,
                color: isCurrent ? 'var(--accent-blue)' : isDone ? 'var(--color-minimal)' : 'var(--text-muted)',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: '6px',
                textAlign: 'center',
              }}
            >
              {isCurrent ? (
                <Loader2 size={16} style={{ animation: 'spin 1.5s linear infinite' }} />
              ) : isDone ? (
                <CheckCircle2 size={16} />
              ) : (
                <Circle size={16} color="var(--text-dim)" />
              )}
              <span>{m.name}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
};
