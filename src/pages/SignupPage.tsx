import React, { useState, useMemo } from 'react';
import { useAuth } from '../context/AuthContext';
import { UserRole } from '../types';
import {
  ShieldAlert,
  Shield,
  Lock,
  Mail,
  User,
  Eye,
  EyeOff,
  ArrowRight,
  AlertTriangle,
  ArrowLeft,
  UserPlus,
  Check,
  X,
} from 'lucide-react';

interface SignupPageProps {
  onNavigateToLogin: () => void;
  onNavigateToHome?: () => void;
}

export const SignupPage: React.FC<SignupPageProps> = ({
  onNavigateToLogin,
  onNavigateToHome,
}) => {
  const { signUpWithEmail, signInWithGoogle, authError, clearAuthError } = useAuth();

  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [role, setRole] = useState<UserRole>('analyst');
  const [acceptedTerms, setAcceptedTerms] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [localError, setLocalError] = useState<string | null>(null);

  // Dynamic Password Strength Evaluation
  const passwordCriteria = useMemo(() => {
    return {
      hasLength: password.length >= 8,
      hasUpper: /[A-Z]/.test(password),
      hasLower: /[a-z]/.test(password),
      hasNumber: /[0-9]/.test(password),
      hasSpecial: /[^A-Za-z0-9]/.test(password),
    };
  }, [password]);

  const passwordScore = useMemo(() => {
    let score = 0;
    if (passwordCriteria.hasLength) score += 1;
    if (passwordCriteria.hasUpper) score += 1;
    if (passwordCriteria.hasLower) score += 1;
    if (passwordCriteria.hasNumber) score += 1;
    if (passwordCriteria.hasSpecial) score += 1;
    return score;
  }, [passwordCriteria]);

  const strengthLabel = useMemo(() => {
    if (password.length === 0) return { text: 'Empty', color: 'bg-slate-700', width: '0%' };
    if (passwordScore <= 2) return { text: 'Weak', color: 'bg-rose-500', width: '25%' };
    if (passwordScore === 3) return { text: 'Fair', color: 'bg-amber-500', width: '50%' };
    if (passwordScore === 4) return { text: 'Good', color: 'bg-cyan-500', width: '75%' };
    return { text: 'Strong', color: 'bg-emerald-500', width: '100%' };
  }, [passwordScore, password]);

  const passwordsMatch = password.length > 0 && confirmPassword.length > 0 && password === confirmPassword;
  const passwordsMismatch = confirmPassword.length > 0 && password !== confirmPassword;

  const handleEmailSignUp = async (e: React.FormEvent) => {
    e.preventDefault();
    clearAuthError();
    setLocalError(null);

    if (!displayName.trim()) {
      setLocalError('Please enter your full name or operator callsign.');
      return;
    }
    if (!email.trim()) {
      setLocalError('Please enter your email address.');
      return;
    }
    if (password.length < 6) {
      setLocalError('Password must be at least 6 characters (8+ recommended).');
      return;
    }
    if (password !== confirmPassword) {
      setLocalError('Passwords do not match. Please re-enter confirmation password.');
      return;
    }
    if (!acceptedTerms) {
      setLocalError('You must acknowledge the authorized scope rules of engagement.');
      return;
    }

    setSubmitting(true);
    try {
      await signUpWithEmail(email, password, displayName, role);
    } catch (err: any) {
      setLocalError(err.message || 'Registration failed. Please check your credentials.');
    } finally {
      setSubmitting(false);
    }
  };

  const handleGoogleSignUp = async () => {
    clearAuthError();
    setLocalError(null);
    setSubmitting(true);
    try {
      await signInWithGoogle();
    } catch (err: any) {
      // Error handled in auth context
    } finally {
      setSubmitting(false);
    }
  };

  const activeError = localError || authError;

  return (
    <div className="min-h-screen bg-[#0B1020] text-slate-100 flex flex-col justify-between selection:bg-blue-600 selection:text-white font-sans">
      {/* Top minimal header */}
      <header className="h-16 border-b border-slate-800/80 px-4 sm:px-6 flex items-center justify-between bg-[#111827]/80 backdrop-blur sticky top-0 z-20">
        <div className="flex items-center gap-3">
          {onNavigateToHome && (
            <button
              onClick={onNavigateToHome}
              className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-white transition-colors cursor-pointer py-1 px-2 rounded-lg hover:bg-slate-800"
              title="Return to Home Landing"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Home</span>
            </button>
          )}

          <div
            onClick={onNavigateToHome}
            className="flex items-center gap-2.5 cursor-pointer group"
          >
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-blue-600 to-cyan-500 flex items-center justify-center shadow-lg shadow-blue-500/20 group-hover:scale-105 transition-transform">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <span className="font-bold tracking-wider text-base text-white">
              RECON<span className="text-cyan-400">X</span>
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 hidden sm:inline">Already have an account?</span>
          <button
            onClick={onNavigateToLogin}
            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-blue-500/20 transition-all cursor-pointer"
          >
            Sign In
          </button>
        </div>
      </header>

      {/* Main Container */}
      <main className="flex-1 flex items-center justify-center p-4 sm:p-6 lg:p-8">
        <div className="w-full max-w-lg my-auto">
          {/* Sign Up Card */}
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 sm:p-8 flex flex-col justify-between shadow-2xl relative">
            <div>
              {/* Form Mode Selector Header */}
              <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-5">
                <div>
                  <h2 className="text-xl font-bold text-white flex items-center gap-2">
                    <UserPlus className="w-5 h-5 text-cyan-400" />
                    Sign Up
                  </h2>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Create your account to get started
                  </p>
                </div>
                <div className="flex p-0.5 bg-slate-900 border border-slate-800 rounded-lg">
                  <button
                    type="button"
                    onClick={onNavigateToLogin}
                    className="px-3 py-1 text-xs font-semibold rounded-md text-slate-400 hover:text-slate-200 transition-colors cursor-pointer"
                  >
                    Sign In
                  </button>
                  <button
                    type="button"
                    className="px-3 py-1 text-xs font-semibold rounded-md bg-blue-600 text-white shadow-sm"
                  >
                    Sign Up
                  </button>
                </div>
              </div>

              {/* Error Banner */}
              {activeError && (
                <div className="mb-4 p-3.5 bg-rose-500/10 border border-rose-500/30 rounded-xl text-xs text-rose-300 flex items-start gap-2.5 animate-fadeIn">
                  <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                  <div className="flex-1">
                    <span className="font-semibold text-rose-200">Registration Error:</span>{' '}
                    {activeError}
                  </div>
                  <button
                    onClick={() => {
                      setLocalError(null);
                      clearAuthError();
                    }}
                    className="text-rose-400 hover:text-rose-200 text-xs cursor-pointer ml-1"
                  >
                    &times;
                  </button>
                </div>
              )}

              {/* Signup Form */}
              <form onSubmit={handleEmailSignUp} className="space-y-3.5">
                {/* Full Name / Callsign */}
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Operator Name / Callsign
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                      <User className="w-4 h-4" />
                    </div>
                    <input
                      type="text"
                      value={displayName}
                      onChange={(e) => setDisplayName(e.target.value)}
                      placeholder="e.g. Alex Vance or SecOps-Lead"
                      required
                      className="w-full bg-[#0B1020] border border-slate-700 rounded-xl pl-9 pr-3.5 py-2 text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all font-sans"
                    />
                  </div>
                </div>

                {/* Email Address */}
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">
                    Work / Institutional Email
                  </label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                      <Mail className="w-4 h-4" />
                    </div>
                    <input
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="operator@security-team.org"
                      required
                      autoComplete="email"
                      className="w-full bg-[#0B1020] border border-slate-700 rounded-xl pl-9 pr-3.5 py-2 text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all font-mono"
                    />
                  </div>
                </div>

                {/* Password & Confirm Grid */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-300 mb-1">
                      Create Password
                    </label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                        <Lock className="w-4 h-4" />
                      </div>
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="Min 6 characters"
                        required
                        autoComplete="new-password"
                        className="w-full bg-[#0B1020] border border-slate-700 rounded-xl pl-9 pr-10 py-2 text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400 transition-all font-mono"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-200 cursor-pointer"
                      >
                        {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                    </div>
                  </div>

                  <div>
                    <div className="flex items-center justify-between mb-1">
                      <label className="block text-xs font-medium text-slate-300">
                        Confirm Password
                      </label>
                      {passwordsMatch && (
                        <span className="text-[10px] text-emerald-400 flex items-center gap-1 font-mono">
                          <Check className="w-3 h-3" /> Match
                        </span>
                      )}
                      {passwordsMismatch && (
                        <span className="text-[10px] text-rose-400 flex items-center gap-1 font-mono">
                          <X className="w-3 h-3" /> Mismatch
                        </span>
                      )}
                    </div>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                        <Lock className="w-4 h-4" />
                      </div>
                      <input
                        type={showPassword ? 'text' : 'password'}
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        placeholder="Re-enter password"
                        required
                        autoComplete="new-password"
                        className={`w-full bg-[#0B1020] border rounded-xl pl-9 pr-3.5 py-2 text-xs sm:text-sm text-slate-100 placeholder-slate-500 focus:outline-none transition-all font-mono ${
                          passwordsMismatch
                            ? 'border-rose-500 focus:border-rose-500'
                            : passwordsMatch
                            ? 'border-emerald-500 focus:border-emerald-500'
                            : 'border-slate-700 focus:border-cyan-400'
                        }`}
                      />
                    </div>
                  </div>
                </div>

                {/* Password Strength Meter */}
                {password.length > 0 && (
                  <div className="p-2.5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-1.5 animate-fadeIn">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-400 font-mono">Password Strength:</span>
                      <span className={`font-semibold text-xs ${
                        passwordScore <= 2 ? 'text-rose-400' : passwordScore === 3 ? 'text-amber-400' : 'text-emerald-400'
                      }`}>
                        {strengthLabel.text}
                      </span>
                    </div>
                    <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
                      <div
                        className={`h-full transition-all duration-300 ${strengthLabel.color}`}
                        style={{ width: strengthLabel.width }}
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-1 text-[10px] text-slate-400 pt-1">
                      <div className={`flex items-center gap-1 ${passwordCriteria.hasLength ? 'text-emerald-400' : ''}`}>
                        <span>•</span> 8+ characters
                      </div>
                      <div className={`flex items-center gap-1 ${passwordCriteria.hasNumber ? 'text-emerald-400' : ''}`}>
                        <span>•</span> Includes number
                      </div>
                      <div className={`flex items-center gap-1 ${passwordCriteria.hasUpper ? 'text-emerald-400' : ''}`}>
                        <span>•</span> Uppercase letter
                      </div>
                      <div className={`flex items-center gap-1 ${passwordCriteria.hasSpecial ? 'text-emerald-400' : ''}`}>
                        <span>•</span> Special symbol
                      </div>
                    </div>
                  </div>
                )}

                {/* Role Selection */}
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1.5 flex items-center justify-between">
                    <span>Operator Assignment</span>
                    <span className="text-[10px] text-slate-500 font-mono">RBAC Profile</span>
                  </label>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <div
                      onClick={() => setRole('analyst')}
                      className={`p-2.5 rounded-xl border cursor-pointer transition-all ${
                        role === 'analyst'
                          ? 'bg-blue-600/15 border-blue-500 text-white shadow-sm'
                          : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-0.5">
                        <span className="text-xs font-semibold text-slate-200">Security Analyst</span>
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300 font-mono">
                          Standard
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400 leading-tight">
                        Launch reconnaissance pipelines, resolve DNS, and probe services.
                      </p>
                    </div>

                    <div
                      onClick={() => setRole('viewer')}
                      className={`p-2.5 rounded-xl border cursor-pointer transition-all ${
                        role === 'viewer'
                          ? 'bg-cyan-600/15 border-cyan-500 text-white shadow-sm'
                          : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between mb-0.5">
                        <span className="text-xs font-semibold text-slate-200">Security Researcher</span>
                        <span className="text-[9px] px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono">
                          Read-Only
                        </span>
                      </div>
                      <p className="text-[10px] text-slate-400 leading-tight">
                        Inspect topologies, review audit trails, and export PDF/CSV reports.
                      </p>
                    </div>
                  </div>
                </div>

                {/* Terms & Scope Authorization Checkbox */}
                <div className="pt-1">
                  <label className="flex items-start gap-2.5 cursor-pointer text-xs text-slate-400 hover:text-slate-300 select-none">
                    <input
                      type="checkbox"
                      checked={acceptedTerms}
                      onChange={(e) => setAcceptedTerms(e.target.checked)}
                      className="w-4 h-4 rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-0 cursor-pointer mt-0.5 shrink-0"
                    />
                    <span className="text-[11px] leading-relaxed">
                      I certify adherence to the <strong className="text-slate-200">ReconX Rules of Engagement</strong> and agree that reconnaissance scans will only target authorized domains, laboratory subnets, or client environments with explicit approval.
                    </span>
                  </label>
                </div>

                {/* Submit button */}
                <button
                  type="submit"
                  disabled={submitting}
                  className="w-full mt-2 py-2.5 sm:py-3 px-4 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl text-xs sm:text-sm font-semibold shadow-lg shadow-cyan-600/20 transition-all cursor-pointer flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {submitting ? (
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  ) : (
                    <>
                      <span>Sign Up</span>
                      <ArrowRight className="w-4 h-4" />
                    </>
                  )}
                </button>
              </form>

              {/* Divider */}
              <div className="relative my-4">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-slate-800" />
                </div>
                <div className="relative flex justify-center text-[10px] uppercase font-mono tracking-wider">
                  <span className="bg-[#111827] px-3 text-slate-500">Or sign up with</span>
                </div>
              </div>

              {/* Google Sign Up */}
              <button
                type="button"
                onClick={handleGoogleSignUp}
                disabled={submitting}
                className="w-full py-2.5 px-4 bg-slate-800/80 hover:bg-slate-750 border border-slate-700 text-slate-200 rounded-xl text-xs sm:text-sm font-semibold transition-all cursor-pointer flex items-center justify-center gap-2.5 shadow-sm hover:border-slate-600 disabled:opacity-50"
              >
                <svg className="w-4 h-4" viewBox="0 0 24 24">
                  <path
                    fill="#4285F4"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                  />
                  <path
                    fill="#EA4335"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                  />
                </svg>
                <span>Sign Up with Google</span>
              </button>
            </div>

            {/* Bottom Footer & Switch to Sign In */}
            <div className="pt-4 mt-4 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between text-xs text-slate-400 gap-2">
              <div>
                <span>Already registered? </span>
                <button
                  type="button"
                  onClick={onNavigateToLogin}
                  className="text-cyan-400 hover:text-cyan-300 font-semibold cursor-pointer underline decoration-cyan-500/40"
                >
                  Sign In
                </button>
              </div>

              <div className="flex items-center gap-1.5 text-[11px] text-slate-500 font-mono">
                <Shield className="w-3.5 h-3.5 text-cyan-400" />
                <span>Zero Trust Architecture</span>
              </div>
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="py-4 border-t border-slate-800/80 text-center text-xs text-slate-500 font-mono">
        ReconX • Authorized Attack Surface Management &amp; Reconnaissance • Secure Transport Layer
      </footer>
    </div>
  );
};
