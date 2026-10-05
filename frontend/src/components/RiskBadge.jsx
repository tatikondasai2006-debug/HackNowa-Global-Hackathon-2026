import React from 'react';

export const RiskBadge = ({ level = 'minimal', size = 'md' }) => {
  const normalized = (level || 'minimal').toLowerCase();

  const labels = {
    critical: 'Critical Risk',
    high: 'High Risk',
    medium: 'Medium Risk',
    low: 'Low Risk',
    minimal: 'Minimal Risk',
  };

  const styleConfigs = {
    sm: { fontSize: '10.5px', padding: '3px 8px', dotSize: '5px' },
    md: { fontSize: '11.5px', padding: '4px 10px', dotSize: '6px' },
    lg: { fontSize: '13px', padding: '6px 14px', dotSize: '7px' },
  };

  const config = styleConfigs[size] || styleConfigs.md;

  return (
    <span
      className={`badge badge-${normalized}`}
      style={{
        fontSize: config.fontSize,
        padding: config.padding,
      }}
    >
      <span
        style={{
          width: config.dotSize,
          height: config.dotSize,
          borderRadius: '50%',
          backgroundColor: 'currentColor',
          display: 'inline-block',
          boxShadow: '0 0 6px currentColor',
        }}
      />
      {labels[normalized] || normalized.toUpperCase()}
    </span>
  );
};
