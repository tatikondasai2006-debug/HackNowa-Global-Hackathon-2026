import React from 'react';

export const SkeletonLoader = ({ type = 'card', count = 1 }) => {
  const renderItem = (index) => {
    if (type === 'card') {
      return (
        <div key={index} className="glass-panel" style={{ padding: '24px', marginBottom: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '16px' }}>
            <div className="skeleton-shimmer" style={{ width: '45%', height: '22px' }} />
            <div className="skeleton-shimmer" style={{ width: '80px', height: '22px' }} />
          </div>
          <div className="skeleton-shimmer" style={{ width: '85%', height: '14px', marginBottom: '10px' }} />
          <div className="skeleton-shimmer" style={{ width: '60%', height: '14px', marginBottom: '20px' }} />
          <div style={{ display: 'flex', gap: '12px' }}>
            <div className="skeleton-shimmer" style={{ width: '100px', height: '32px' }} />
            <div className="skeleton-shimmer" style={{ width: '120px', height: '32px' }} />
          </div>
        </div>
      );
    }

    if (type === 'stats') {
      return (
        <div key={index} className="glass-panel" style={{ padding: '24px', display: 'flex', alignItems: 'center', gap: '20px' }}>
          <div className="skeleton-shimmer" style={{ width: '90px', height: '90px', borderRadius: '50%' }} />
          <div style={{ flex: 1 }}>
            <div className="skeleton-shimmer" style={{ width: '40%', height: '12px', marginBottom: '10px' }} />
            <div className="skeleton-shimmer" style={{ width: '60%', height: '28px', marginBottom: '8px' }} />
            <div className="skeleton-shimmer" style={{ width: '80%', height: '12px' }} />
          </div>
        </div>
      );
    }

    if (type === 'table') {
      return (
        <div key={index} className="glass-panel" style={{ padding: '20px', marginBottom: '16px' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {[1, 2, 3, 4, 5].map((row) => (
              <div key={row} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255,255,255,0.04)', paddingBottom: '12px' }}>
                <div className="skeleton-shimmer" style={{ width: '25%', height: '16px' }} />
                <div className="skeleton-shimmer" style={{ width: '15%', height: '16px' }} />
                <div className="skeleton-shimmer" style={{ width: '10%', height: '16px' }} />
                <div className="skeleton-shimmer" style={{ width: '15%', height: '16px' }} />
                <div className="skeleton-shimmer" style={{ width: '80px', height: '28px' }} />
              </div>
            ))}
          </div>
        </div>
      );
    }

    return <div key={index} className="skeleton-shimmer" style={{ width: '100%', height: '100px', marginBottom: '16px' }} />;
  };

  return <>{Array.from({ length: count }).map((_, i) => renderItem(i))}</>;
};
