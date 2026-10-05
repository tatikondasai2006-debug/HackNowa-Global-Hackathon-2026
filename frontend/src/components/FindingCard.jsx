import React, { useState } from 'react';
import { RiskBadge } from './RiskBadge';
import { Bot, ChevronDown, ChevronUp, Copy, Check, ShieldAlert, Code2, Wrench, Sparkles, ExternalLink } from 'lucide-react';
import { api } from '../services/api';
import { StatusBanner } from './StatusBanner';

export const FindingCard = ({ finding, aiDetail = null }) => {
  const [expanded, setExpanded] = useState(false);
  const [activeTab, setActiveTab] = useState('remediation'); // 'remediation' | 'evidence' | 'ai'
  const [aiExplanation, setAiExplanation] = useState(() => {
    if (aiDetail) {
      return [
        aiDetail.explanation,
        aiDetail.why_it_matters ? `Why it matters: ${aiDetail.why_it_matters}` : '',
        aiDetail.impact ? `Impact: ${aiDetail.impact}` : '',
        Array.isArray(aiDetail.remediation) && aiDetail.remediation.length
          ? `Fix: ${aiDetail.remediation.join(' ')}`
          : '',
      ].filter(Boolean).join('\n\n');
    }
    return finding.ai_explanation || null;
  });
  const [loadingAi, setLoadingAi] = useState(false);
  const [aiError, setAiError] = useState('');
  const [copied, setCopied] = useState(false);

  const handleAskAI = async (e) => {
    e?.stopPropagation();
    setExpanded(true);
    setActiveTab('ai');
    if (aiExplanation) return;

    setLoadingAi(true);
    setAiError('');
    try {
      const response = await api.explainFinding(finding.id);
      setAiExplanation(response.explanation);
    } catch (err) {
      setAiError(err.message || 'Failed to generate AI explanation');
    } finally {
      setLoadingAi(false);
    }
  };

  const handleCopyEvidence = () => {
    if (finding.evidence) {
      navigator.clipboard.writeText(finding.evidence);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const severityBorderColors = {
    critical: 'var(--color-critical)',
    high: 'var(--color-high)',
    medium: 'var(--color-medium)',
    low: 'var(--color-low)',
    info: 'var(--color-info)',
  };

  return (
    <div
      className="glass-panel"
      style={{
        marginBottom: '16px',
        borderLeft: `4px solid ${severityBorderColors[finding.severity] || 'var(--border-subtle)'}`,
        padding: '20px 24px',
        overflow: 'hidden',
      }}
    >
      {/* Header Row */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '16px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', gap: '14px', alignItems: 'flex-start', flex: 1, minWidth: '280px' }}>
          <div
            style={{
              marginTop: '2px',
              padding: '8px',
              borderRadius: '8px',
              background: 'rgba(255, 255, 255, 0.04)',
              color: severityBorderColors[finding.severity] || 'var(--accent-blue)',
            }}
          >
            <ShieldAlert size={20} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-white)' }}>{finding.title}</h3>
              <RiskBadge level={finding.severity} size="sm" />
              <span
                style={{
                  fontSize: '11px',
                  color: 'var(--text-muted)',
                  background: 'rgba(255, 255, 255, 0.05)',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  fontWeight: 600,
                  border: '1px solid var(--border-subtle)',
                }}
              >
                {finding.category}
              </span>
            </div>
            <p style={{ fontSize: '13.5px', color: 'var(--text-muted)', marginTop: '6px', lineHeight: 1.5 }}>
              {finding.description}
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button
            type="button"
            onClick={handleAskAI}
            className="btn btn-secondary"
            style={{
              padding: '7px 12px',
              fontSize: '12px',
              borderColor: 'rgba(139, 92, 246, 0.4)',
              color: 'var(--accent-violet)',
              background: 'rgba(139, 92, 246, 0.08)',
            }}
            title="Ask AI Copilot to explain this finding"
          >
            <Sparkles size={14} />
            <span>{loadingAi ? 'Analyzing...' : 'AI Explain'}</span>
          </button>

          <button
            type="button"
            onClick={() => setExpanded(!expanded)}
            className="btn btn-secondary"
            style={{ padding: '7px 10px', color: 'var(--text-muted)' }}
            aria-label={expanded ? 'Collapse Finding Details' : 'Expand Finding Details'}
            aria-expanded={expanded}
          >
            {expanded ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
          </button>
        </div>
      </div>

      {/* Expandable Tabs */}
      {expanded && (
        <div style={{ marginTop: '20px', paddingTop: '16px', borderTop: '1px solid var(--border-subtle)' }}>
          {/* Tab Selector */}
          <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
            <button
              type="button"
              onClick={() => setActiveTab('remediation')}
              className={`btn ${activeTab === 'remediation' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '12.5px', padding: '6px 14px' }}
            >
              <Wrench size={14} /> Remediation Guidance
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('evidence')}
              className={`btn ${activeTab === 'evidence' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '12.5px', padding: '6px 14px' }}
            >
              <Code2 size={14} /> Technical Evidence
            </button>
            <button
              type="button"
              onClick={() => { setActiveTab('ai'); if (!aiExplanation) handleAskAI(); }}
              className={`btn ${activeTab === 'ai' ? 'btn-primary' : 'btn-ghost'}`}
              style={{ fontSize: '12.5px', padding: '6px 14px' }}
            >
              <Bot size={14} /> AI Plain-English Analysis
            </button>
          </div>

          {/* Tab Content: Remediation */}
          {activeTab === 'remediation' && (
            <div
              style={{
                background: 'rgba(56, 189, 248, 0.04)',
                border: '1px solid rgba(56, 189, 248, 0.15)',
                borderLeft: '3px solid var(--accent-blue)',
                padding: '16px 20px',
                borderRadius: '0 8px 8px 0',
                fontSize: '13.5px',
              }}
            >
              <div style={{ fontWeight: 700, color: 'var(--accent-blue)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Wrench size={15} /> Recommended Fix Guidance:
              </div>
              <p style={{ color: 'var(--text-main)', lineHeight: 1.6 }}>
                {finding.recommendation || 'Apply standard defensive baseline security configuration.'}
              </p>
              {Array.isArray(finding.remediation_steps) && finding.remediation_steps.length > 0 && (
                <ol style={{ marginTop: '12px', paddingLeft: '18px', color: 'var(--text-main)', lineHeight: 1.6 }}>
                  {finding.remediation_steps.map((step, idx) => (
                    <li key={idx} style={{ marginBottom: '6px' }}>{step}</li>
                  ))}
                </ol>
              )}
              {Array.isArray(finding.reference_urls) && finding.reference_urls.length > 0 && (
                <div style={{ marginTop: '14px', paddingTop: '10px', borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
                  <span style={{ fontSize: '11.5px', color: 'var(--text-dim)', fontWeight: 600, display: 'block', marginBottom: '6px' }}>
                    STANDARDS & REFERENCES:
                  </span>
                  {finding.reference_urls.map((url) => (
                    <a
                      key={url}
                      href={url}
                      target="_blank"
                      rel="noreferrer"
                      style={{ display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '12px', marginRight: '14px', color: 'var(--accent-blue)' }}
                    >
                      <ExternalLink size={12} /> {url}
                    </a>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab Content: Technical Evidence */}
          {activeTab === 'evidence' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)' }}>
                  RAW DIAGNOSTIC RESPONSE & HEADERS:
                </span>
                {finding.evidence && (
                  <button
                    type="button"
                    onClick={handleCopyEvidence}
                    className="btn btn-ghost"
                    style={{ fontSize: '11px', padding: '4px 8px', color: copied ? 'var(--color-minimal)' : 'var(--text-muted)' }}
                  >
                    {copied ? <Check size={12} /> : <Copy size={12} />}
                    <span>{copied ? 'Copied' : 'Copy Evidence'}</span>
                  </button>
                )}
              </div>
              <pre
                style={{
                  background: '#040711',
                  border: '1px solid var(--border-subtle)',
                  padding: '14px 18px',
                  borderRadius: '8px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '12.5px',
                  color: 'var(--accent-cyan)',
                  overflowX: 'auto',
                  whiteSpace: 'pre-wrap',
                  lineHeight: 1.5,
                }}
              >
                {finding.evidence || 'No technical raw payload required for this finding.'}
              </pre>
            </div>
          )}

          {/* Tab Content: AI Deep Dive */}
          {activeTab === 'ai' && (
            <div
              style={{
                background: 'rgba(139, 92, 246, 0.05)',
                border: '1px solid rgba(139, 92, 246, 0.2)',
                borderLeft: '3px solid var(--accent-violet)',
                padding: '16px 20px',
                borderRadius: '0 8px 8px 0',
                fontSize: '13.5px',
                lineHeight: 1.6,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent-violet)', fontWeight: 700, marginBottom: '8px' }}>
                <Bot size={16} />
                <span>AI Plain-English Business Risk Analysis:</span>
              </div>
              {aiError && <StatusBanner type="error" style={{ marginBottom: '10px' }}>{aiError}</StatusBanner>}
              {loadingAi ? (
                <div style={{ color: 'var(--text-muted)', fontSize: '13px', padding: '8px 0' }}>
                  Synthesizing business risk impact analysis and remediation advice...
                </div>
              ) : (
                <div style={{ whiteSpace: 'pre-line', color: 'var(--text-main)' }}>
                  {aiExplanation || 'Click AI Explain above to synthesize grounded insights from the stored finding evidence.'}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
