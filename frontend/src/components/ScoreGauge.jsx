import React from 'react';

export const ScoreGauge = ({ score = 0, size = 160, showGrade = true }) => {
  const normalizedScore = Math.max(0, Math.min(100, Math.round(score || 0)));
  const strokeWidth = size >= 140 ? 12 : 9;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 100) * circumference;

  let color = 'var(--color-critical)';
  let grade = 'F';
  let gradientId = 'grad-critical';

  if (normalizedScore >= 90) {
    color = 'var(--color-minimal)';
    grade = 'A+';
    gradientId = 'grad-minimal';
  } else if (normalizedScore >= 75) {
    color = 'var(--accent-blue)';
    grade = 'A';
    gradientId = 'grad-low';
  } else if (normalizedScore >= 55) {
    color = 'var(--color-medium)';
    grade = 'B';
    gradientId = 'grad-medium';
  } else if (normalizedScore >= 35) {
    color = 'var(--color-high)';
    grade = 'C';
    gradientId = 'grad-high';
  }

  return (
    <div
      style={{
        position: 'relative',
        width: `${size}px`,
        height: `${size}px`,
        display: 'inline-flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)', overflow: 'visible' }}>
        <defs>
          <linearGradient id="grad-minimal" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#10b981" />
            <stop offset="100%" stopColor="#06b6d4" />
          </linearGradient>
          <linearGradient id="grad-low" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#0284c7" />
            <stop offset="100%" stopColor="#38bdf8" />
          </linearGradient>
          <linearGradient id="grad-medium" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#f59e0b" />
            <stop offset="100%" stopColor="#fbbf24" />
          </linearGradient>
          <linearGradient id="grad-high" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#ea580c" />
            <stop offset="100%" stopColor="#f97316" />
          </linearGradient>
          <linearGradient id="grad-critical" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#e11d48" />
            <stop offset="100%" stopColor="#f43f5e" />
          </linearGradient>
          <filter id="glow-gauge" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feComposite in="SourceGraphic" in2="blur" operator="over" />
          </filter>
        </defs>

        {/* Background Track */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke="rgba(255, 255, 255, 0.06)"
          strokeWidth={strokeWidth}
        />

        {/* Progress Arc */}
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          fill="transparent"
          stroke={`url(#${gradientId})`}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          filter="url(#glow-gauge)"
          style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(0.16, 1, 0.3, 1)' }}
        />
      </svg>

      {/* Inner Label */}
      <div
        style={{
          position: 'absolute',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          textAlign: 'center',
          userSelect: 'none',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'baseline', gap: '2px' }}>
          <span
            style={{
              fontSize: `${size * 0.28}px`,
              fontWeight: 900,
              fontFamily: 'var(--font-display)',
              color: 'var(--text-white)',
              lineHeight: 1,
              letterSpacing: '-0.03em',
            }}
          >
            {normalizedScore}
          </span>
          <span style={{ fontSize: `${size * 0.12}px`, color: 'var(--text-muted)', fontWeight: 600 }}>/100</span>
        </div>

        {showGrade && (
          <span
            style={{
              fontSize: `${size * 0.085}px`,
              fontWeight: 800,
              color,
              textTransform: 'uppercase',
              letterSpacing: '0.08em',
              marginTop: '4px',
            }}
          >
            GRADE {grade}
          </span>
        )}
      </div>
    </div>
  );
};
