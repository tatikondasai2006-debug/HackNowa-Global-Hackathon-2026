import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Shield, Lock, FileText, Bot, ArrowRight, CheckCircle2, ShieldCheck,
  Zap, Globe, Mail, Network, HelpCircle, ChevronDown, ChevronUp, Sparkles,
  Server, Cpu, Check, AlertTriangle
} from 'lucide-react';

export const LandingPage = () => {
  const [openFaq, setOpenFaq] = useState(null);

  const faqs = [
    {
      q: 'Will running a scan affect or slow down my live website?',
      a: 'No. CyberSentinel only performs non-invasive passive diagnostics (reading public SSL certs, DNS records, HTTP response headers, and safe connection handshakes). It sends minimal traffic equivalent to standard browser visits.'
    },
    {
      q: 'What makes CyberSentinel different from basic online SSL checkers?',
      a: 'CyberSentinel performs a holistic multi-vector perimeter audit—combining TLS cipher strength, OWASP security headers, DNSSEC & CAA integrity, SPF/DKIM/DMARC email defenses, and exposed services into a single unified score backed by a cited RAG AI consultant.'
    },
    {
      q: 'Are the AI recommendations trustworthy and grounded?',
      a: 'Yes. Our AI engine is strictly constrained by Retrieval-Augmented Generation (RAG) mapped directly against NIST CSF, OWASP Top 10, and CIS defensive standards with direct source citations, eliminating hallucinated vulnerabilities.'
    },
    {
      q: 'Can I export reports for compliance or client presentations?',
      a: 'Yes. Every completed assessment generates an instant print-ready executive report in both HTML and PDF formats with severity breakdowns, evidence snippets, and clear remediation action plans.'
    },
    {
      q: 'Do I need to install any software or agents on my server?',
      a: 'No agents or server modifications required. The entire audit is executed non-invasively against public internet-facing endpoints.'
    }
  ];

  const toggleFaq = (idx) => {
    setOpenFaq(openFaq === idx ? null : idx);
  };

  return (
    <div style={{ position: 'relative' }}>
      {/* Background cyber mesh */}
      <div className="cyber-bg" />

      {/* Hero Section */}
      <section style={{ padding: '80px 0 60px', textAlign: 'center', position: 'relative' }}>
        <div className="layout-container" style={{ maxWidth: '980px' }}>
          {/* Top Pill */}
          <div
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '8px',
              padding: '6px 16px',
              borderRadius: '9999px',
              background: 'rgba(56, 189, 248, 0.08)',
              border: '1px solid rgba(56, 189, 248, 0.25)',
              color: 'var(--accent-blue)',
              fontSize: '13px',
              fontWeight: 700,
              marginBottom: '24px',
              boxShadow: 'var(--shadow-glow-blue)',
            }}
          >
            <Sparkles size={14} className="animate-pulse-glow" />
            <span>Autonomous Passive Cyber Risk Assessment for Small Businesses</span>
          </div>

          <h1
            style={{
              fontSize: 'clamp(36px, 5vw, 54px)',
              fontWeight: 900,
              letterSpacing: '-0.03em',
              marginBottom: '20px',
              lineHeight: 1.15,
            }}
          >
            Enterprise-Grade Perimeter Security Auditing Built for{' '}
            <span className="gradient-text">Small Business</span>
          </h1>

          <p
            style={{
              fontSize: 'clamp(16px, 2vw, 18px)',
              color: 'var(--text-muted)',
              marginBottom: '36px',
              lineHeight: 1.6,
              maxWidth: '800px',
              margin: '0 auto 36px',
            }}
          >
            Safely audit your website’s public security posture in seconds. Discover missing security headers, weak TLS protocols, email spoofing vulnerabilities, and exposed ports — backed by deterministic scoring and grounded AI remediation.
          </p>

          <div style={{ display: 'flex', justifyContent: 'center', gap: '14px', flexWrap: 'wrap', marginBottom: '50px' }}>
            <Link to="/register" className="btn btn-primary" style={{ padding: '14px 28px', fontSize: '15px' }}>
              Launch Free Security Audit <ArrowRight size={17} />
            </Link>
            <Link to="/login" className="btn btn-secondary" style={{ padding: '14px 26px', fontSize: '15px' }}>
              Sign In to Command Center
            </Link>
          </div>

          {/* Realistic Visual Audit Preview Terminal */}
          <div
            className="glass-panel"
            style={{
              textAlign: 'left',
              border: '1px solid rgba(56, 189, 248, 0.25)',
              borderRadius: 'var(--radius-lg)',
              overflow: 'hidden',
              boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6), 0 0 35px rgba(56, 189, 248, 0.15)',
              marginBottom: '40px',
            }}
          >
            {/* Terminal Header */}
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '12px 20px',
                background: 'rgba(5, 8, 20, 0.95)',
                borderBottom: '1px solid var(--border-subtle)',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#ef4444' }} />
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#f59e0b' }} />
                <div style={{ width: '10px', height: '10px', borderRadius: '50%', background: '#10b981' }} />
                <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginLeft: '8px' }}>
                  cybersentinel-probe --target yourcompany.com
                </span>
              </div>
              <span style={{ fontSize: '11px', color: 'var(--accent-blue)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                PASSIVE SCAN ENGINE
              </span>
            </div>

            {/* Terminal Body */}
            <div style={{ padding: '24px', display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '16px', background: 'rgba(8, 14, 32, 0.75)' }}>
              <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>TLS / SSL Trust</span>
                  <CheckCircle2 size={15} color="var(--color-minimal)" />
                </div>
                <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-white)' }}>TLS 1.3 Active</div>
                <span style={{ fontSize: '11px', color: 'var(--color-minimal)' }}>Grade A+ Valid Cert</span>
              </div>

              <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>OWASP Headers</span>
                  <CheckCircle2 size={15} color="var(--color-minimal)" />
                </div>
                <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-white)' }}>HSTS Enforced</div>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>CSP & Anti-Clickjacking</span>
              </div>

              <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>Email Anti-Spoof</span>
                  <CheckCircle2 size={15} color="var(--color-minimal)" />
                </div>
                <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-white)' }}>DMARC Reject</div>
                <span style={{ fontSize: '11px', color: 'var(--color-minimal)' }}>SPF & DKIM Validated</span>
              </div>

              <div style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '14px', borderRadius: '8px', border: '1px solid var(--border-subtle)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: 600 }}>Port Surface</span>
                  <CheckCircle2 size={15} color="var(--color-minimal)" />
                </div>
                <div style={{ fontSize: '15px', fontWeight: 800, color: 'var(--text-white)' }}>Perimeter Safe</div>
                <span style={{ fontSize: '11px', color: 'var(--color-minimal)' }}>No Exposed DB Ports</span>
              </div>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div
            className="glass-panel"
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
              padding: '24px',
              gap: '16px',
              textAlign: 'center',
            }}
          >
            <div>
              <div style={{ fontSize: '28px', fontWeight: 900, color: 'var(--accent-blue)', fontFamily: 'var(--font-display)' }}>100%</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Non-Invasive</div>
            </div>
            <div>
              <div style={{ fontSize: '28px', fontWeight: 900, color: 'var(--accent-violet)', fontFamily: 'var(--font-display)' }}>20+</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Security Checks</div>
            </div>
            <div>
              <div style={{ fontSize: '28px', fontWeight: 900, color: 'var(--accent-cyan)', fontFamily: 'var(--font-display)' }}>0–100</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Deterministic Score</div>
            </div>
            <div>
              <div style={{ fontSize: '28px', fontWeight: 900, color: 'var(--color-minimal)', fontFamily: 'var(--font-display)' }}>&lt; 30s</div>
              <div style={{ fontSize: '12px', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Audit Duration</div>
            </div>
          </div>
        </div>
      </section>

      {/* Feature Pillars Grid */}
      <section style={{ padding: '60px 0' }}>
        <div className="layout-container">
          <div style={{ textAlign: 'center', marginBottom: '48px' }}>
            <h2 style={{ fontSize: '32px', fontWeight: 800, marginBottom: '10px' }}>
              Multi-Vector Security Diagnostic Suite
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '15px', maxWidth: '600px', margin: '0 auto' }}>
              Comprehensive defensive assessments aligning with NIST, OWASP, and CIS frameworks.
            </p>
          </div>

          <div className="grid-cols-3">
            <div className="glass-panel-interactive" style={{ padding: '30px' }}>
              <div style={{ background: 'rgba(56, 189, 248, 0.1)', padding: '12px', borderRadius: '12px', width: 'fit-content', color: 'var(--accent-blue)', marginBottom: '20px', border: '1px solid rgba(56, 189, 248, 0.2)' }}>
                <Lock size={24} />
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 700, marginBottom: '10px' }}>TLS & Cryptography</h3>
              <p style={{ fontSize: '13.5px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Audits certificate trust chains, expiration timelines, hostname validation, and deprecation of legacy TLS 1.0/1.1 protocols.
              </p>
            </div>

            <div className="glass-panel-interactive" style={{ padding: '30px' }}>
              <div style={{ background: 'rgba(139, 92, 246, 0.1)', padding: '12px', borderRadius: '12px', width: 'fit-content', color: 'var(--accent-violet)', marginBottom: '20px', border: '1px solid rgba(139, 92, 246, 0.2)' }}>
                <ShieldCheck size={24} />
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 700, marginBottom: '10px' }}>OWASP Header Defense</h3>
              <p style={{ fontSize: '13.5px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Checks HSTS enforcement, Content-Security-Policy (CSP), anti-clickjacking protection, and verifies server stack headers aren't leaked.
              </p>
            </div>

            <div className="glass-panel-interactive" style={{ padding: '30px' }}>
              <div style={{ background: 'rgba(6, 182, 212, 0.1)', padding: '12px', borderRadius: '12px', width: 'fit-content', color: 'var(--accent-cyan)', marginBottom: '20px', border: '1px solid rgba(6, 182, 212, 0.2)' }}>
                <Mail size={24} />
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 700, marginBottom: '10px' }}>Email Anti-Spoofing</h3>
              <p style={{ fontSize: '13.5px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Evaluates SPF records, DMARC reject policies, and DKIM keys to safeguard your domain from phishing and spoofing impersonation.
              </p>
            </div>

            <div className="glass-panel-interactive" style={{ padding: '30px' }}>
              <div style={{ background: 'rgba(16, 185, 129, 0.1)', padding: '12px', borderRadius: '12px', width: 'fit-content', color: 'var(--color-minimal)', marginBottom: '20px', border: '1px solid rgba(16, 185, 129, 0.2)' }}>
                <Globe size={24} />
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 700, marginBottom: '10px' }}>DNS & DNSSEC Integrity</h3>
              <p style={{ fontSize: '13.5px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Verifies cryptographic DNSSEC signatures, CAA certificate restrictions, and nameserver redundancy for resilient DNS infrastructure.
              </p>
            </div>

            <div className="glass-panel-interactive" style={{ padding: '30px' }}>
              <div style={{ background: 'rgba(249, 115, 22, 0.1)', padding: '12px', borderRadius: '12px', width: 'fit-content', color: 'var(--color-high)', marginBottom: '20px', border: '1px solid rgba(249, 115, 22, 0.2)' }}>
                <Network size={24} />
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 700, marginBottom: '10px' }}>Exposed Port Detection</h3>
              <p style={{ fontSize: '13.5px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Defensively inspects public ports to detect accidental exposure of critical database (MySQL/Postgres) or remote desktop (RDP) services.
              </p>
            </div>

            <div className="glass-panel-interactive" style={{ padding: '30px' }}>
              <div style={{ background: 'rgba(192, 132, 252, 0.1)', padding: '12px', borderRadius: '12px', width: 'fit-content', color: 'var(--accent-purple)', marginBottom: '20px', border: '1px solid rgba(192, 132, 252, 0.2)' }}>
                <Bot size={24} />
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 700, marginBottom: '10px' }}>Grounded RAG AI Advisor</h3>
              <p style={{ fontSize: '13.5px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Ask questions in plain English and receive cited, step-by-step remediation advice backed directly by industry security standards.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* How It Works Workflow */}
      <section style={{ padding: '60px 0', borderTop: '1px solid var(--border-subtle)', background: 'rgba(10, 16, 36, 0.4)' }}>
        <div className="layout-container">
          <div style={{ textAlign: 'center', marginBottom: '48px' }}>
            <h2 style={{ fontSize: '32px', fontWeight: 800, marginBottom: '10px' }}>
              How CyberSentinel Protects Your Business
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '15px', maxWidth: '600px', margin: '0 auto' }}>
              From initial validation to executive remediation in three automated steps.
            </p>
          </div>

          <div className="grid-cols-3">
            <div className="glass-panel" style={{ padding: '32px 24px', textAlign: 'center' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: 'rgba(56, 189, 248, 0.15)', border: '1px solid var(--accent-blue)', color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, margin: '0 auto 16px', fontSize: '16px' }}>
                1
              </div>
              <h3 style={{ fontSize: '17px', fontWeight: 700, marginBottom: '10px' }}>1. Scope & Verification</h3>
              <p style={{ fontSize: '13.5px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Submit target domain with strict authorization attestation and SSRF validation protecting against private network scanning.
              </p>
            </div>

            <div className="glass-panel" style={{ padding: '32px 24px', textAlign: 'center' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: 'rgba(139, 92, 246, 0.15)', border: '1px solid var(--accent-violet)', color: 'var(--accent-violet)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, margin: '0 auto 16px', fontSize: '16px' }}>
                2
              </div>
              <h3 style={{ fontSize: '17px', fontWeight: 700, marginBottom: '10px' }}>2. Passive Diagnostic Run</h3>
              <p style={{ fontSize: '13.5px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Scanners safely probe public TLS, HTTP headers, DNSSEC, email security records, and open ports concurrently.
              </p>
            </div>

            <div className="glass-panel" style={{ padding: '32px 24px', textAlign: 'center' }}>
              <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: 'rgba(16, 185, 129, 0.15)', border: '1px solid var(--color-minimal)', color: 'var(--color-minimal)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, margin: '0 auto 16px', fontSize: '16px' }}>
                3
              </div>
              <h3 style={{ fontSize: '17px', fontWeight: 700, marginBottom: '10px' }}>3. Deterministic Rating & RAG</h3>
              <p style={{ fontSize: '13.5px', color: 'var(--text-muted)', lineHeight: 1.6 }}>
                Calculates a transparent 0-100 score, lists severity findings, and provides grounded AI remediation and downloadable reports.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Interactive FAQ Section */}
      <section style={{ padding: '60px 0', borderTop: '1px solid var(--border-subtle)' }}>
        <div className="layout-container" style={{ maxWidth: '820px' }}>
          <div style={{ textAlign: 'center', marginBottom: '40px' }}>
            <h2 style={{ fontSize: '28px', fontWeight: 800, marginBottom: '8px' }}>Frequently Asked Questions</h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '14px' }}>Everything you need to know about our passive assessment platform.</p>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {faqs.map((faq, idx) => {
              const isOpen = openFaq === idx;
              return (
                <div
                  key={idx}
                  className="glass-panel"
                  style={{
                    padding: '18px 24px',
                    cursor: 'pointer',
                    borderColor: isOpen ? 'var(--accent-blue)' : undefined,
                    transition: 'border-color 0.2s ease',
                  }}
                  onClick={() => toggleFaq(idx)}
                >
                  <button
                    type="button"
                    style={{
                      width: '100%',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      background: 'none',
                      border: 'none',
                      color: 'inherit',
                      textAlign: 'left',
                      fontFamily: 'inherit',
                      cursor: 'pointer',
                      padding: 0,
                    }}
                    aria-expanded={isOpen}
                  >
                    <span style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-white)' }}>{faq.q}</span>
                    {isOpen ? <ChevronUp size={18} color="var(--accent-blue)" /> : <ChevronDown size={18} color="var(--text-muted)" />}
                  </button>
                  {isOpen && (
                    <p style={{ fontSize: '14px', color: 'var(--text-muted)', marginTop: '12px', lineHeight: 1.6, borderTop: '1px solid var(--border-subtle)', paddingTop: '12px' }}>
                      {faq.a}
                    </p>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </section>

      {/* CTA Footer Banner */}
      <section style={{ padding: '60px 0 80px' }}>
        <div className="layout-container" style={{ maxWidth: '920px' }}>
          <div
            className="glass-panel-glow"
            style={{
              padding: '48px 36px',
              textAlign: 'center',
              background: 'linear-gradient(135deg, rgba(2, 132, 199, 0.18) 0%, rgba(139, 92, 246, 0.18) 100%)',
            }}
          >
            <h2 style={{ fontSize: '32px', fontWeight: 800, marginBottom: '12px' }}>
              Protect Your Small Business Perimeter Today
            </h2>
            <p style={{ color: 'var(--text-muted)', fontSize: '15px', maxWidth: '600px', margin: '0 auto 28px' }}>
              Run your first scan in under 30 seconds with no software installation or agent deployment required.
            </p>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '14px', flexWrap: 'wrap' }}>
              <Link to="/register" className="btn btn-primary" style={{ padding: '14px 32px', fontSize: '15px' }}>
                Get Started Free <ArrowRight size={17} />
              </Link>
              <Link to="/login" className="btn btn-secondary" style={{ padding: '14px 28px', fontSize: '15px' }}>
                Existing User Sign In
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Simple Professional Footer */}
      <footer style={{ borderTop: '1px solid var(--border-subtle)', padding: '32px 0', background: 'rgba(5, 8, 20, 0.9)' }}>
        <div className="layout-container" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px', fontSize: '13px', color: 'var(--text-dim)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Shield size={16} color="var(--accent-blue)" />
            <span>CyberSentinel © 2026 — Defensive Cybersecurity Diagnostic Platform</span>
          </div>
          <div style={{ display: 'flex', gap: '20px' }}>
            <span>NIST CSF Aligned</span>
            <span>OWASP Standards</span>
            <span>CIS Controls Grounded</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
