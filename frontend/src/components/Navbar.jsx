import React, { useState } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, LayoutDashboard, Search, History, Bot, LogOut, Menu, X, Sparkles } from 'lucide-react';

export const Navbar = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const handleLogout = () => {
    logout();
    navigate('/');
    setMobileMenuOpen(false);
  };

  const isActive = (path) => {
    if (path === '/dashboard') {
      return location.pathname === '/dashboard';
    }
    return location.pathname.startsWith(path);
  };

  const navItems = [
    { label: 'Dashboard', path: '/dashboard', icon: LayoutDashboard },
    { label: 'New Scan', path: '/scan/new', icon: Search },
    { label: 'Scan History', path: '/history', icon: History },
    { label: 'AI Advisor', path: '/rag-assistant', icon: Bot },
  ];

  return (
    <nav
      aria-label="Main Navigation"
      style={{
        borderBottom: '1px solid var(--border-subtle)',
        background: 'rgba(5, 8, 20, 0.88)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        padding: '12px 0',
      }}
    >
      <div className="layout-container" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        {/* Brand Logo */}
        <Link
          to={user ? '/dashboard' : '/'}
          style={{ display: 'flex', alignItems: 'center', gap: '12px', textDecoration: 'none' }}
          onClick={() => setMobileMenuOpen(false)}
          aria-label="CyberSentinel Home"
        >
          <div
            style={{
              background: 'linear-gradient(135deg, #0284c7 0%, #6366f1 100%)',
              padding: '8px',
              borderRadius: '10px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 20px rgba(56, 189, 248, 0.35)',
              border: '1px solid rgba(255, 255, 255, 0.2)',
            }}
          >
            <Shield size={22} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '19px', fontWeight: 800, letterSpacing: '-0.02em' }} className="gradient-text">
                CyberSentinel
              </span>
              <span
                style={{
                  fontSize: '10px',
                  background: 'rgba(56, 189, 248, 0.12)',
                  color: 'var(--accent-blue)',
                  padding: '2px 7px',
                  borderRadius: '9999px',
                  fontWeight: 700,
                  border: '1px solid rgba(56, 189, 248, 0.25)',
                }}
              >
                PRO
              </span>
            </div>
            <span style={{ fontSize: '10.5px', display: 'block', color: 'var(--text-muted)', fontWeight: 600, marginTop: '-2px', letterSpacing: '0.04em' }}>
              PERIMETER SECURITY AUDITOR
            </span>
          </div>
        </Link>

        {/* Desktop Navigation */}
        {user ? (
          <div className="desktop-nav" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            {navItems.map((item) => {
              const Icon = item.icon;
              const active = isActive(item.path);
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`btn ${active ? 'btn-primary' : 'btn-ghost'}`}
                  style={{
                    padding: '8px 14px',
                    fontSize: '13px',
                    borderRadius: '8px',
                  }}
                  aria-current={active ? 'page' : undefined}
                >
                  <Icon size={15} />
                  <span>{item.label}</span>
                </Link>
              );
            })}

            <div style={{ width: '1px', height: '22px', background: 'var(--border-subtle)', margin: '0 10px' }} />

            {/* User info & Signout */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '6px 14px',
                  background: 'rgba(255, 255, 255, 0.04)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  fontSize: '13px',
                }}
              >
                <div
                  style={{
                    width: '8px',
                    height: '8px',
                    borderRadius: '50%',
                    background: 'var(--color-minimal)',
                    boxShadow: '0 0 8px var(--color-minimal)',
                  }}
                  title="Session Active"
                />
                <span style={{ color: 'var(--text-main)', fontWeight: 600 }}>{user.username}</span>
              </div>

              <button
                onClick={handleLogout}
                className="btn btn-secondary"
                style={{ padding: '8px 12px' }}
                title="Sign Out"
                aria-label="Sign Out"
              >
                <LogOut size={15} />
              </button>
            </div>
          </div>
        ) : (
          <div className="desktop-nav" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <Link to="/login" className="btn btn-ghost" style={{ fontSize: '13.5px' }}>
              Sign In
            </Link>
            <Link to="/register" className="btn btn-primary" style={{ padding: '9px 18px', fontSize: '13.5px' }}>
              <Sparkles size={15} /> Get Started Free
            </Link>
          </div>
        )}

        {/* Mobile Toggle Button */}
        <div className="mobile-toggle" style={{ display: 'none' }}>
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="btn btn-ghost"
            style={{ padding: '8px' }}
            aria-label={mobileMenuOpen ? 'Close Navigation Menu' : 'Open Navigation Menu'}
            aria-expanded={mobileMenuOpen}
          >
            {mobileMenuOpen ? <X size={22} /> : <Menu size={22} />}
          </button>
        </div>
      </div>

      {/* Mobile Drawer */}
      {mobileMenuOpen && (
        <div
          style={{
            background: 'var(--bg-surface)',
            borderTop: '1px solid var(--border-subtle)',
            padding: '20px 24px',
            display: 'flex',
            flexDirection: 'column',
            gap: '10px',
            animation: 'floatSmooth 0.2s ease-out',
          }}
        >
          {user ? (
            <>
              {navItems.map((item) => {
                const Icon = item.icon;
                const active = isActive(item.path);
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    onClick={() => setMobileMenuOpen(false)}
                    className={`btn ${active ? 'btn-primary' : 'btn-secondary'}`}
                    style={{ justifyContent: 'flex-start', padding: '12px 16px' }}
                    aria-current={active ? 'page' : undefined}
                  >
                    <Icon size={16} />
                    <span>{item.label}</span>
                  </Link>
                );
              })}
              <div style={{ height: '1px', background: 'var(--border-subtle)', margin: '4px 0' }} />
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 4px', fontSize: '13px', color: 'var(--text-muted)' }}>
                <span>Signed in as: <strong style={{ color: 'var(--text-white)' }}>{user.username}</strong></span>
              </div>
              <button
                onClick={handleLogout}
                className="btn btn-danger"
                style={{ justifyContent: 'flex-start', padding: '12px 16px' }}
              >
                <LogOut size={16} />
                <span>Sign Out</span>
              </button>
            </>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <Link
                to="/login"
                onClick={() => setMobileMenuOpen(false)}
                className="btn btn-secondary"
                style={{ justifyContent: 'center' }}
              >
                Sign In
              </Link>
              <Link
                to="/register"
                onClick={() => setMobileMenuOpen(false)}
                className="btn btn-primary"
                style={{ justifyContent: 'center' }}
              >
                <Sparkles size={15} /> Get Started Free
              </Link>
            </div>
          )}
        </div>
      )}

      <style>{`
        @media (max-width: 768px) {
          .desktop-nav { display: none !important; }
          .mobile-toggle { display: block !important; }
        }
      `}</style>
    </nav>
  );
};
