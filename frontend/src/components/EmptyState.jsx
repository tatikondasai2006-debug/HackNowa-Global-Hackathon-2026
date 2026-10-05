import React from 'react';
import { Link } from 'react-router-dom';
import { ShieldCheck, Plus, ArrowRight } from 'lucide-react';

export const EmptyState = ({
  icon: Icon = ShieldCheck,
  title = 'No Data Available',
  description = 'No active records or findings discovered yet.',
  actionLabel,
  actionTo,
  actionOnClick,
}) => {
  return (
    <div
      className="glass-panel"
      style={{
        textAlign: 'center',
        padding: '56px 24px',
        maxWidth: '520px',
        margin: '20px auto',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
      }}
    >
      <div
        style={{
          width: '64px',
          height: '64px',
          borderRadius: '50%',
          background: 'rgba(56, 189, 248, 0.08)',
          border: '1px solid rgba(56, 189, 248, 0.2)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: 'var(--accent-blue)',
          marginBottom: '20px',
          boxShadow: 'var(--shadow-glow-blue)',
        }}
      >
        <Icon size={28} />
      </div>

      <h3 style={{ fontSize: '18px', fontWeight: 700, marginBottom: '8px', color: 'var(--text-white)' }}>
        {title}
      </h3>
      <p style={{ fontSize: '14px', color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: actionLabel ? '24px' : '0' }}>
        {description}
      </p>

      {actionLabel && actionTo && (
        <Link to={actionTo} className="btn btn-primary">
          <Plus size={16} /> {actionLabel}
        </Link>
      )}

      {actionLabel && actionOnClick && (
        <button onClick={actionOnClick} className="btn btn-primary">
          <Plus size={16} /> {actionLabel}
        </button>
      )}
    </div>
  );
};
