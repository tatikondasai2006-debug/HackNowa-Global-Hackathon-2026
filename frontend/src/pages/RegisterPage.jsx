import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { Shield, Lock, Mail, User, Building, ArrowRight, Sparkles } from 'lucide-react';
import { StatusBanner } from '../components/StatusBanner';

export const RegisterPage = () => {
  const [formData, setFormData] = useState({
    email: '',
    username: '',
    password: '',
    full_name: '',
    company_name: '',
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const { register } = useAuth();
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!/^[a-zA-Z0-9_-]{3,50}$/.test(formData.username)) {
      setError('Username must be 3–50 characters: letters, numbers, underscores, or hyphens.');
      return;
    }
    if (formData.password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }
    if (!/[A-Z]/.test(formData.password) || !/[a-z]/.test(formData.password) || !/[0-9]/.test(formData.password)) {
      setError('Password must include uppercase, lowercase, and a number.');
      return;
    }

    setLoading(true);

    try {
      await register({
        ...formData,
        company_name: formData.company_name || null,
        full_name: formData.full_name || null,
      });
      navigate('/dashboard');
    } catch (err) {
      setError(err.message || 'Registration failed. Please check your details.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: 'calc(100vh - 140px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '40px 20px' }}>
      <div className="glass-panel" style={{ width: '100%', maxWidth: '480px', padding: '36px', boxShadow: '0 20px 50px rgba(0, 0, 0, 0.6), var(--shadow-glow-blue)' }}>
        <div style={{ textAlign: 'center', marginBottom: '28px' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              borderRadius: '12px',
              background: 'linear-gradient(135deg, #0284c7, #6366f1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              margin: '0 auto 12px',
              boxShadow: 'var(--shadow-glow-blue)',
            }}
          >
            <Shield size={26} color="#fff" />
          </div>
          <h1 style={{ fontSize: '24px', fontWeight: 800 }}>Create Your Account</h1>
          <p style={{ fontSize: '13.5px', color: 'var(--text-muted)', marginTop: '4px' }}>
            Start auditing your small business perimeter today
          </p>
        </div>

        {error && <StatusBanner type="error">{error}</StatusBanner>}

        <form onSubmit={handleSubmit}>
          <div className="grid-cols-2" style={{ gap: '12px', marginBottom: '16px' }}>
            <div>
              <label className="input-label" htmlFor="register-username">Username</label>
              <input
                id="register-username"
                type="text"
                name="username"
                required
                className="input-field"
                placeholder="cyberadmin"
                value={formData.username}
                onChange={handleChange}
              />
            </div>

            <div>
              <label className="input-label" htmlFor="register-company">Company Name</label>
              <input
                id="register-company"
                type="text"
                name="company_name"
                className="input-field"
                placeholder="Acme Corp"
                value={formData.company_name}
                onChange={handleChange}
              />
            </div>
          </div>

          <div className="input-group">
            <label className="input-label" htmlFor="register-email">Email Address</label>
            <input
              id="register-email"
              type="email"
              name="email"
              required
              className="input-field"
              placeholder="you@company.com"
              value={formData.email}
              onChange={handleChange}
            />
          </div>

          <div className="input-group">
            <label className="input-label" htmlFor="register-password">Password (Min 8 chars, 1 uppercase, 1 number)</label>
            <input
              id="register-password"
              type="password"
              name="password"
              required
              className="input-field"
              placeholder="••••••••"
              value={formData.password}
              onChange={handleChange}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn btn-primary"
            style={{ width: '100%', padding: '12px', marginTop: '8px', height: '46px' }}
          >
            {loading ? 'Creating Account...' : 'Get Started Free'} <ArrowRight size={16} />
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: '24px', fontSize: '13px', color: 'var(--text-muted)' }}>
          Already have an account?{' '}
          <Link to="/login" style={{ fontWeight: 600, color: 'var(--accent-blue)' }}>
            Sign In
          </Link>
        </div>
      </div>
    </div>
  );
};
