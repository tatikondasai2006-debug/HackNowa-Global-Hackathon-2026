import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { api } from '../services/api';
import { StatusBanner } from '../components/StatusBanner';
import { domainValidationMessage, sanitizeDomain } from '../utils/domain';
import {
  Lock, ShieldCheck, Globe, Mail, Network,
  ArrowRight, Sparkles, Sliders, Shield, AlertTriangle, CheckCircle2
} from 'lucide-react';

const DEFAULT_OPTIONS = {
  tls: true,
  https: true,
  headers: true,
  dns: true,
  email_security: true,
  ports: true,
};

export const NewScanPage = () => {
  const [searchParams] = useSearchParams();
  const [domain, setDomain] = useState(searchParams.get('domain') || '');
  const [options, setOptions] = useState(DEFAULT_OPTIONS);
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [phase, setPhase] = useState('');
  const [error, setError] = useState('');
  const [validation, setValidation] = useState(null);
  const [fieldError, setFieldError] = useState('');
  const [selectedPreset, setSelectedPreset] = useState('full');

  const navigate = useNavigate();

  useEffect(() => {
    const preset = searchParams.get('domain');
    if (preset) setDomain(preset);
  }, [searchParams]);

  const handleToggle = (key) => {
    setSelectedPreset('custom');
    setOptions((prev) => {
      const next = { ...prev, [key]: !prev[key] };
      if (key === 'tls') next.https = next.tls;
      return next;
    });
  };

  const setPreset = (preset) => {
    setSelectedPreset(preset);
    if (preset === 'full') {
      setOptions({ ...DEFAULT_OPTIONS });
    } else if (preset === 'web') {
      setOptions({ tls: true, https: true, headers: true, dns: true, email_security: false, ports: false });
    } else if (preset === 'email') {
      setOptions({ tls: true, https: true, headers: false, dns: true, email_security: true, ports: false });
    }
  };

  const anyModuleSelected = Object.values(options).some(Boolean);

  const handleStartScan = async (e) => {
    e.preventDefault();
    setError('');
    setValidation(null);

    if (!authorized) {
      setError('You must confirm you are authorized to assess this domain before launching the scan.');
      return;
    }

    const clean = sanitizeDomain(domain);
    const formatError = domainValidationMessage(clean);
    if (formatError) {
      setFieldError(formatError);
      setError(formatError);
      return;
    }
    setFieldError('');

    if (!anyModuleSelected) {
      setError('Please select at least one scan diagnostic module.');
      return;
    }

    setLoading(true);
    try {
      setPhase('Validating domain with DNS resolver & SSRF guard…');
      const preflight = await api.validateDomain(clean, true);
      if (!preflight.valid) {
        setError(preflight.message || 'Domain failed backend validation.');
        setLoading(false);
        setPhase('');
        return;
      }
      setValidation(preflight);

      setPhase('Creating assessment job and initiating live probes…');
      const scanJob = await api.startScan(preflight.domain || clean, options, authorized);
      navigate(`/scan/${scanJob.id}`);
    } catch (err) {
      setError(err.message || 'Scan initialization failed. Please verify domain name and server connectivity.');
      setLoading(false);
      setPhase('');
    }
  };

  return (
    <div className="layout-container" style={{ padding: '40px 24px', maxWidth: '820px' }}>
      <div style={{ textAlign: 'center', marginBottom: '36px' }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '5px 16px',
            borderRadius: '9999px',
            background: 'rgba(56, 189, 248, 0.08)',
            border: '1px solid rgba(56, 189, 248, 0.25)',
            color: 'var(--accent-blue)',
            fontSize: '12.5px',
            fontWeight: 700,
            marginBottom: '14px',
            boxShadow: 'var(--shadow-glow-blue)',
          }}
        >
          <Sparkles size={14} className="animate-pulse-glow" /> Autonomous Perimeter Diagnostics
        </div>

        <h1 style={{ fontSize: '32px', fontWeight: 800, color: 'var(--text-white)' }}>
          Launch New Security Assessment
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '14.5px', marginTop: '6px' }}>
          Real-time passive probes audit your public perimeter, calculate deterministic posture, and generate grounded remediation.
        </p>
      </div>

      {error && <StatusBanner type="error">{error}</StatusBanner>}
      {validation?.valid && (
        <StatusBanner type="success">
          Domain verified: {validation.domain}
          {validation.addresses?.length ? ` (${validation.addresses.join(', ')})` : ''}
        </StatusBanner>
      )}
      {phase && <StatusBanner type="info">{phase}</StatusBanner>}

      <div className="glass-panel" style={{ padding: '36px' }}>
        <form onSubmit={handleStartScan}>
          {/* Target Domain Input */}
          <div style={{ marginBottom: '28px' }}>
            <label htmlFor="target-domain-input" className="input-label" style={{ fontSize: '13.5px' }}>
              Target Domain or FQDN
            </label>
            <div style={{ position: 'relative' }}>
              <input
                id="target-domain-input"
                type="text"
                required
                className="input-field"
                style={{
                  paddingLeft: '44px',
                  height: '48px',
                  fontSize: '15px',
                  fontWeight: 500,
                  borderColor: fieldError ? 'rgba(244, 63, 94, 0.6)' : undefined,
                }}
                placeholder="company.com"
                value={domain}
                onChange={(e) => {
                  setDomain(e.target.value);
                  setFieldError('');
                  setValidation(null);
                }}
                onBlur={() => {
                  const clean = sanitizeDomain(domain);
                  if (domain && domainValidationMessage(clean)) {
                    setFieldError(domainValidationMessage(clean));
                  }
                }}
              />
              <Globe size={18} color="var(--text-muted)" style={{ position: 'absolute', left: '16px', top: '15px' }} />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '12px', color: fieldError ? '#fb7185' : 'var(--text-dim)', marginTop: '6px' }}>
              <span>{fieldError || 'Do not include protocols (https://) or URL paths.'}</span>
              <span>SSRF protected</span>
            </div>
          </div>

          {/* Configuration Presets */}
          <div style={{ marginBottom: '24px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <span style={{ fontSize: '13.5px', fontWeight: 700, color: 'var(--text-muted)' }}>
                Audit Configuration Presets
              </span>
              <span style={{ fontSize: '12px', color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Sliders size={13} /> Select Scope
              </span>
            </div>

            <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={() => setPreset('full')}
                className={`btn ${selectedPreset === 'full' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '12.5px', padding: '8px 16px' }}
              >
                Comprehensive 360° (Recommended)
              </button>
              <button
                type="button"
                onClick={() => setPreset('web')}
                className={`btn ${selectedPreset === 'web' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '12.5px', padding: '8px 16px' }}
              >
                Web & SSL Only
              </button>
              <button
                type="button"
                onClick={() => setPreset('email')}
                className={`btn ${selectedPreset === 'email' ? 'btn-primary' : 'btn-secondary'}`}
                style={{ fontSize: '12.5px', padding: '8px 16px' }}
              >
                Email Security (SPF/DMARC)
              </button>
            </div>
          </div>

          {/* Module Checklist */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginBottom: '28px' }}>
            {/* Module: TLS/SSL */}
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '14px 18px',
                background: options.tls ? 'rgba(56, 189, 248, 0.04)' : 'rgba(255, 255, 255, 0.02)',
                border: options.tls ? '1px solid rgba(56, 189, 248, 0.3)' : '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <div style={{ padding: '8px', borderRadius: '8px', background: 'rgba(56, 189, 248, 0.1)', color: 'var(--accent-blue)' }}>
                  <Lock size={18} />
                </div>
                <div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-white)' }}>TLS / SSL & HTTPS Verification</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Certificate trust chain, cipher strength, expiration, HTTPS redirection</div>
                </div>
              </div>
              <input
                type="checkbox"
                checked={options.tls}
                onChange={() => handleToggle('tls')}
                style={{ width: '18px', height: '18px', accentColor: 'var(--accent-blue)', cursor: 'pointer' }}
              />
            </label>

            {/* Module: Headers */}
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '14px 18px',
                background: options.headers ? 'rgba(139, 92, 246, 0.04)' : 'rgba(255, 255, 255, 0.02)',
                border: options.headers ? '1px solid rgba(139, 92, 246, 0.3)' : '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <div style={{ padding: '8px', borderRadius: '8px', background: 'rgba(139, 92, 246, 0.1)', color: 'var(--accent-violet)' }}>
                  <ShieldCheck size={18} />
                </div>
                <div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-white)' }}>HTTP Security Headers (OWASP)</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>HSTS max-age, CSP policy, X-Frame-Options, server header leakage</div>
                </div>
              </div>
              <input
                type="checkbox"
                checked={options.headers}
                onChange={() => handleToggle('headers')}
                style={{ width: '18px', height: '18px', accentColor: 'var(--accent-violet)', cursor: 'pointer' }}
              />
            </label>

            {/* Module: DNS */}
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '14px 18px',
                background: options.dns ? 'rgba(6, 182, 212, 0.04)' : 'rgba(255, 255, 255, 0.02)',
                border: options.dns ? '1px solid rgba(6, 182, 212, 0.3)' : '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <div style={{ padding: '8px', borderRadius: '8px', background: 'rgba(6, 182, 212, 0.1)', color: 'var(--accent-cyan)' }}>
                  <Globe size={18} />
                </div>
                <div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-white)' }}>DNSSEC & CAA Records</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>DNSSEC cryptographic validation, CAA certificate authority restrictions</div>
                </div>
              </div>
              <input
                type="checkbox"
                checked={options.dns}
                onChange={() => handleToggle('dns')}
                style={{ width: '18px', height: '18px', accentColor: 'var(--accent-cyan)', cursor: 'pointer' }}
              />
            </label>

            {/* Module: Email */}
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '14px 18px',
                background: options.email_security ? 'rgba(56, 189, 248, 0.04)' : 'rgba(255, 255, 255, 0.02)',
                border: options.email_security ? '1px solid rgba(56, 189, 248, 0.3)' : '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <div style={{ padding: '8px', borderRadius: '8px', background: 'rgba(56, 189, 248, 0.1)', color: 'var(--accent-blue)' }}>
                  <Mail size={18} />
                </div>
                <div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-white)' }}>Email Anti-Spoofing (SPF / DMARC)</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>SPF record syntax, DMARC enforcement policies, DKIM selector check</div>
                </div>
              </div>
              <input
                type="checkbox"
                checked={options.email_security}
                onChange={() => handleToggle('email_security')}
                style={{ width: '18px', height: '18px', accentColor: 'var(--accent-blue)', cursor: 'pointer' }}
              />
            </label>

            {/* Module: Ports */}
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '14px 18px',
                background: options.ports ? 'rgba(168, 85, 247, 0.04)' : 'rgba(255, 255, 255, 0.02)',
                border: options.ports ? '1px solid rgba(168, 85, 247, 0.3)' : '1px solid var(--border-subtle)',
                borderRadius: 'var(--radius-sm)',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                <div style={{ padding: '8px', borderRadius: '8px', background: 'rgba(168, 85, 247, 0.1)', color: 'var(--accent-purple)' }}>
                  <Network size={18} />
                </div>
                <div>
                  <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-white)' }}>Exposed Ports & Services</div>
                  <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Safe connection check against exposed databases (MySQL/Postgres) and RDP</div>
                </div>
              </div>
              <input
                type="checkbox"
                checked={options.ports}
                onChange={() => handleToggle('ports')}
                style={{ width: '18px', height: '18px', accentColor: 'var(--accent-purple)', cursor: 'pointer' }}
              />
            </label>
          </div>

          {/* Legal Authorization Confirmation Box */}
          <div
            style={{
              marginBottom: '28px',
              padding: '16px 20px',
              background: authorized ? 'rgba(16, 185, 129, 0.05)' : 'rgba(244, 63, 94, 0.05)',
              borderRadius: 'var(--radius-sm)',
              border: authorized ? '1px solid rgba(16, 185, 129, 0.3)' : '1px solid rgba(244, 63, 94, 0.35)',
              transition: 'all 0.2s ease',
            }}
          >
            <label
              htmlFor="scan-authorization"
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '12px',
                cursor: 'pointer',
                fontSize: '13px',
                color: authorized ? 'var(--text-main)' : '#fca5a5',
                lineHeight: 1.5,
              }}
            >
              <input
                id="scan-authorization"
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                style={{ marginTop: '3px', width: '16px', height: '16px', accentColor: 'var(--accent-blue)', cursor: 'pointer' }}
              />
              <span>
                <strong>Authorization Confirmation:</strong> I confirm that I own this target domain or have explicit written permission from its owner to conduct this perimeter assessment. Unauthorized port and network scanning may violate regional computer crime laws. This attestation is permanently recorded in the audit log.
              </span>
            </label>
          </div>

          {/* Launch Button */}
          <button
            type="submit"
            disabled={loading || !domain.trim() || !authorized || !anyModuleSelected}
            className="btn btn-primary"
            style={{ width: '100%', padding: '14px', fontSize: '15px', height: '50px' }}
          >
            {loading ? (phase || 'Launching Diagnostics…') : 'Launch Security Assessment'} <ArrowRight size={17} />
          </button>
        </form>
      </div>
    </div>
  );
};
