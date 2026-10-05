import React from 'react';
import { AlertCircle, CheckCircle2, Info } from 'lucide-react';

const STYLES = {
  error: {
    background: 'rgba(244, 63, 94, 0.12)',
    border: '1px solid rgba(244, 63, 94, 0.3)',
    color: '#fb7185',
    Icon: AlertCircle,
  },
  success: {
    background: 'rgba(16, 185, 129, 0.12)',
    border: '1px solid rgba(16, 185, 129, 0.3)',
    color: '#34d399',
    Icon: CheckCircle2,
  },
  info: {
    background: 'rgba(56, 189, 248, 0.12)',
    border: '1px solid rgba(56, 189, 248, 0.3)',
    color: 'var(--accent-cyan)',
    Icon: Info,
  },
};

export const StatusBanner = ({ type = 'error', children, style }) => {
  if (!children) return null;
  const config = STYLES[type] || STYLES.error;
  const Icon = config.Icon;

  return (
    <div
      role={type === 'error' ? 'alert' : 'status'}
      style={{
        background: config.background,
        border: config.border,
        padding: '12px 16px',
        borderRadius: 'var(--radius-sm)',
        color: config.color,
        fontSize: '13.5px',
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        marginBottom: '20px',
        ...style,
      }}
    >
      <Icon size={16} style={{ flexShrink: 0 }} />
      <span>{children}</span>
    </div>
  );
};
