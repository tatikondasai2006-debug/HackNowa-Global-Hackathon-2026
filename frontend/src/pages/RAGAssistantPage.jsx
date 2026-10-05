import React, { useState, useRef, useEffect } from 'react';
import { api } from '../services/api';
import { StatusBanner } from '../components/StatusBanner';
import { Bot, Send, BookOpen, Sparkles, User, HelpCircle, Shield, ArrowRight } from 'lucide-react';

export const RAGAssistantPage = () => {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: 'Welcome to the CyberSentinel AI Security Advisor. I am grounded in NIST CSF, OWASP Top 10, and CIS defensive standards. Ask me how to remediate specific scan findings, configure strict DMARC/SPF policies, implement HSTS headers, or harden your perimeter against attacks.',
      sources: []
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [scans, setScans] = useState([]);
  const [scanJobId, setScanJobId] = useState('');
  const [loadError, setLoadError] = useState('');
  const messagesEndRef = useRef(null);

  useEffect(() => {
    api.getScans(1, 50, { status: 'completed' })
      .then((data) => setScans(data.scans || []))
      .catch((err) => setLoadError(err.message || 'Could not load scan context list'));
  }, []);

  const suggestedQuestions = [
    'How do I configure a strict DMARC policy for Google Workspace?',
    'What is HSTS and why does CyberSentinel recommend 31536000 max-age?',
    'How do I prevent server header information disclosure in Nginx?',
    'What is the difference between SPF ~all (softfail) and -all (fail)?'
  ];

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, loading]);

  const handleSend = async (questionText = null) => {
    const q = (questionText || input).trim();
    if (!q || loading) return;

    if (q.length < 5) {
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: 'Please provide a question of at least 5 characters so the RAG engine can retrieve relevant defensive standards.', sources: [] },
      ]);
      return;
    }

    const userMessage = { role: 'user', content: q };
    setMessages((prev) => [...prev, userMessage]);
    setInput('');
    setLoading(true);

    try {
      const response = await api.askRAG(q, scanJobId ? Number(scanJobId) : null);
      const assistantMessage = {
        role: 'assistant',
        content: response.answer,
        sources: response.sources || [],
        is_ai_generated: response.is_ai_generated,
        scan_context_used: response.scan_context_used,
      };
      setMessages((prev) => [...prev, assistantMessage]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          content: err.message || 'The RAG API could not answer this question. Please confirm the backend server is running.',
          sources: []
        }
      ]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="layout-container" style={{ padding: '40px 24px', maxWidth: '920px' }}>
      {/* Top Header */}
      <div style={{ textAlign: 'center', marginBottom: '32px' }}>
        <div
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '5px 16px',
            borderRadius: '9999px',
            background: 'rgba(139, 92, 246, 0.08)',
            border: '1px solid rgba(139, 92, 246, 0.25)',
            color: 'var(--accent-violet)',
            fontSize: '12.5px',
            fontWeight: 700,
            marginBottom: '12px',
            boxShadow: 'var(--shadow-glow-violet)',
          }}
        >
          <Sparkles size={14} className="animate-pulse-glow" /> Verifiable Grounded RAG Pipeline
        </div>
        <h1 style={{ fontSize: '32px', fontWeight: 800, color: 'var(--text-white)' }}>
          Cybersecurity AI Security Advisor
        </h1>
        <p style={{ color: 'var(--text-muted)', fontSize: '14.5px', marginTop: '4px' }}>
          Ask questions grounded in NIST, OWASP, and CIS defensive standards with direct source citations.
        </p>
      </div>

      {loadError && <StatusBanner type="error">{loadError}</StatusBanner>}

      {/* Optional Scan Context Selector */}
      <div className="glass-panel" style={{ padding: '16px 20px', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent-blue)', fontWeight: 600, fontSize: '13px' }}>
          <Shield size={16} />
          <span>Audit Context:</span>
        </div>
        <div style={{ flex: 1, minWidth: '240px' }}>
          <select
            className="input-field"
            value={scanJobId}
            onChange={(e) => setScanJobId(e.target.value)}
            style={{ height: '38px', fontSize: '13px', padding: '6px 12px' }}
            aria-label="Select scan context"
          >
            <option value="">Knowledge base only (general defense)</option>
            {scans.map((scan) => (
              <option key={scan.id} value={scan.id}>
                #{scan.id} {scan.target_domain} ({scan.overall_score != null ? `Score: ${Math.round(scan.overall_score)}` : 'Pending'})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Suggested Questions Bar */}
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', marginBottom: '20px' }}>
        {suggestedQuestions.map((q, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => handleSend(q)}
            className="btn btn-secondary"
            style={{ fontSize: '12px', padding: '6px 12px', borderRadius: 'var(--radius-full)' }}
          >
            <HelpCircle size={13} color="var(--accent-blue)" /> {q}
          </button>
        ))}
      </div>

      {/* Chat Thread Panel */}
      <div
        className="glass-panel"
        style={{
          padding: '24px',
          minHeight: '480px',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          marginBottom: '20px',
        }}
      >
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: '20px',
            overflowY: 'auto',
            maxHeight: '520px',
            paddingRight: '8px',
          }}
        >
          {messages.map((msg, index) => (
            <div
              key={index}
              style={{
                display: 'flex',
                gap: '12px',
                alignItems: 'flex-start',
                alignSelf: msg.role === 'user' ? 'flex-end' : 'flex-start',
                maxWidth: '90%',
              }}
            >
              {msg.role === 'assistant' && (
                <div
                  style={{
                    background: 'rgba(139, 92, 246, 0.12)',
                    border: '1px solid rgba(139, 92, 246, 0.25)',
                    padding: '8px',
                    borderRadius: '8px',
                    color: 'var(--accent-violet)',
                    flexShrink: 0,
                  }}
                >
                  <Bot size={18} />
                </div>
              )}

              <div
                style={{
                  background: msg.role === 'user' ? 'linear-gradient(135deg, #0284c7 0%, #6366f1 100%)' : 'rgba(255, 255, 255, 0.03)',
                  border: msg.role === 'user' ? 'none' : '1px solid var(--border-subtle)',
                  borderRadius: '12px',
                  padding: '16px 20px',
                  fontSize: '14px',
                  lineHeight: 1.6,
                  color: 'var(--text-white)',
                  whiteSpace: 'pre-wrap',
                }}
              >
                <div>{msg.content}</div>

                {/* Sources & Citations Box */}
                {msg.sources && msg.sources.length > 0 && (
                  <div
                    style={{
                      marginTop: '14px',
                      paddingTop: '12px',
                      borderTop: '1px solid rgba(255, 255, 255, 0.08)',
                      fontSize: '12px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: 'var(--accent-cyan)', fontWeight: 700, marginBottom: '6px' }}>
                      <BookOpen size={13} />
                      <span>Retrieved Defensive Standards & Citations:</span>
                    </div>
                    {msg.sources.map((s, sIdx) => (
                      <div key={sIdx} style={{ color: 'var(--text-muted)', marginLeft: '16px', fontSize: '11.5px', marginTop: '3px' }}>
                        • <strong>{s.title}</strong> <span style={{ color: 'var(--text-dim)' }}>({s.source})</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {msg.role === 'user' && (
                <div
                  style={{
                    background: 'rgba(56, 189, 248, 0.12)',
                    border: '1px solid rgba(56, 189, 248, 0.25)',
                    padding: '8px',
                    borderRadius: '8px',
                    color: 'var(--accent-blue)',
                    flexShrink: 0,
                  }}
                >
                  <User size={18} />
                </div>
              )}
            </div>
          ))}

          {loading && (
            <div style={{ display: 'flex', gap: '12px', alignItems: 'center', color: 'var(--accent-violet)', fontSize: '13px', padding: '8px 0' }}>
              <Bot size={18} className="animate-pulse-glow" />
              <span>Retrieving knowledge base documents & formulating cited guidance...</span>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* Input Bar */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          style={{ display: 'flex', gap: '10px', marginTop: '20px', paddingTop: '16px', borderTop: '1px solid var(--border-subtle)' }}
        >
          <input
            type="text"
            className="input-field"
            placeholder="Ask a technical security or configuration question..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            disabled={loading}
            style={{ flex: 1, height: '46px', fontSize: '14px' }}
            aria-label="Your cybersecurity question"
          />
          <button
            type="submit"
            disabled={loading || !input.trim()}
            className="btn btn-primary"
            style={{ padding: '0 20px', height: '46px' }}
            aria-label="Send question"
          >
            <Send size={16} />
          </button>
        </form>
      </div>
    </div>
  );
};
