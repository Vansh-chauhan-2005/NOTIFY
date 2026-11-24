import React, { useState, useEffect, useRef } from 'react';
import {
  Smartphone,
  Mail,
  ArrowRight,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  Lock,
  ChevronLeft,
  KeyRound,
} from 'lucide-react';
import { AegisGlyphLogo } from './NothingLogos.js';
import {
  auth,
  googleAuthProvider,
  signInWithPopup,
  syncFirebaseUserProfile,
  formatFirebasePhoneError,
} from '../lib/firebase/client.js';
import { safeReadJson } from '../lib/http/safeJson.js';

interface LoginPageProps {
  onLoginSuccess: (user: { id: string; phoneNumber?: string; email?: string; role: string }) => void;
}

const COUNTRY_CODES = [
  { code: '+91', country: 'IN', flag: '🇮🇳' },
  { code: '+1', country: 'US / CA', flag: '🇺🇸' },
  { code: '+44', country: 'UK', flag: '🇬🇧' },
  { code: '+61', country: 'AU', flag: '🇦🇺' },
  { code: '+49', country: 'DE', flag: '🇩🇪' },
  { code: '+33', country: 'FR', flag: '🇫🇷' },
  { code: '+81', country: 'JP', flag: '🇯🇵' },
  { code: '+65', country: 'SG', flag: '🇸🇬' },
  { code: '+971', country: 'UAE', flag: '🇦🇪' },
];

export default function LoginPage({ onLoginSuccess }: LoginPageProps) {
  // Primary mode: 'otp' (Mobile SMS or Email OTP) or 'password' (Admin Key)
  const [authMode, setAuthMode] = useState<'otp' | 'password'>('otp');
  const [otpChannel, setOtpChannel] = useState<'sms' | 'email'>('sms');

  // OTP Login Flow States
  const [countryCode, setCountryCode] = useState('+91');
  const [rawPhone, setRawPhone] = useState('');
  const [otpEmail, setOtpEmail] = useState('rajputvanshc@gmail.com');
  const [otpStep, setOtpStep] = useState<'enter_destination' | 'enter_otp'>('enter_destination');
  const [otpDigits, setOtpDigits] = useState<string[]>(['', '', '', '', '', '']);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);
  const [cooldown, setCooldown] = useState(0);
  const [emailLive, setEmailLive] = useState<boolean | null>(null);
  const [emailVerified, setEmailVerified] = useState<boolean | null>(null);
  const [emailGatewayNotice, setEmailGatewayNotice] = useState<string | null>(null);
  const [smsAllowedCountries, setSmsAllowedCountries] = useState<string[]>(['+91']);

  // Admin Email & Key flow
  const [adminEmail, setAdminEmail] = useState('rajputvanshc@gmail.com');
  const [adminPassword, setAdminPassword] = useState('Admin@Aegis2026!');

  const otpInputsRef = useRef<(HTMLInputElement | null)[]>([]);

  // Check server email & SMS gateway readiness on mount
  useEffect(() => {
    fetch('/api/v1/auth/otp/send')
      .then((res) => safeReadJson(res))
      .then((data) => {
        if (!data?.success) {
          setEmailLive(false);
          setEmailVerified(false);
          return;
        }
        setEmailLive(Boolean(data.emailConfigured));
        setEmailVerified(typeof data.emailVerified === 'boolean' ? data.emailVerified : Boolean(data.emailConfigured));
        setEmailGatewayNotice(data.emailError || null);
      })
      .catch(() => {
        setEmailLive(false);
        setEmailVerified(false);
      });

    fetch('/api/v1/auth/sms/status')
      .then((res) => safeReadJson(res))
      .then((data) => {
        if (data?.success && data?.data) {
          if (Array.isArray(data.data.allowedCountries) && data.data.allowedCountries.length > 0) {
            setSmsAllowedCountries(data.data.allowedCountries);
            if (!data.data.allowedCountries.includes(countryCode)) {
              setCountryCode(data.data.allowedCountries[0]);
            }
          }
        }
      })
      .catch(() => {
        // Keep defaults cleanly on network blip
      });

  }, []);

  // Cooldown timer
  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setInterval(() => {
      setCooldown((prev) => (prev <= 1 ? 0 : prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [cooldown]);

  const fullPhoneNumber = `${countryCode}${rawPhone.trim().replace(/\D/g, '')}`;
  const activeOtpDestination = otpChannel === 'sms' ? fullPhoneNumber : otpEmail.trim().toLowerCase();

  // Send OTP (Twilio Verify / Mock SMS for Mobile SMS OR node_auth.js + Nodemailer for Email)
  const handleSendOtp = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    setErrorMsg(null);
    setStatusMsg(null);

    if (otpChannel === 'sms') {
      const cleanNumber = rawPhone.trim().replace(/\D/g, '');
      if (cleanNumber.length < 7) {
        setErrorMsg('Please enter a valid mobile number.');
        return;
      }

      setIsLoading(true);
      try {
        const res = await fetch('/api/v1/auth/sms/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ phone: fullPhoneNumber }),
        });

        const data = await safeReadJson(res);
        if (!res.ok || !data.success) {
          setErrorMsg(data.message || 'Failed to send SMS verification code.');
          if (data.data?.cooldownSeconds) {
            setCooldown(data.data.cooldownSeconds);
          }
          return;
        }

        setStatusMsg(
          data.message ||
            `Verification code sent to ${data.data?.maskedPhone || fullPhoneNumber}.`
        );
        setCooldown(data.data?.cooldownSeconds || 60);
        setOtpStep('enter_otp');
        setOtpDigits(['', '', '', '', '', '']);
        setTimeout(() => {
          otpInputsRef.current[0]?.focus();
        }, 100);
      } catch (err: any) {
        setErrorMsg(`Network error: ${err?.message || 'Unable to send SMS code.'}`);
      } finally {
        setIsLoading(false);
      }
      return;
    }

    // Email OTP via node_auth.js + live SMTP
    const cleanEmail = otpEmail.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanEmail)) {
      setErrorMsg('Please enter a valid email address.');
      return;
    }

    setIsLoading(true);
    try {
      const res = await fetch('/api/v1/auth/otp/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ destination: cleanEmail }),
      });

      const data = await safeReadJson(res);

      if (!res.ok || !data.success) {
        setErrorMsg(data.message || data.error || 'Failed to deliver verification email.');
        if (data.cooldownSeconds) {
          setCooldown(data.cooldownSeconds);
        }
        return;
      }

      setStatusMsg(data.message || `Verification code sent to ${cleanEmail}`);
      setCooldown(data.cooldownSeconds || 60);
      setOtpStep('enter_otp');
      setOtpDigits(['', '', '', '', '', '']);
      setTimeout(() => {
        otpInputsRef.current[0]?.focus();
      }, 100);
    } catch (err: any) {
      setErrorMsg(`Network error: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Digit input handlers for OTP Login
  const handleOtpChange = (index: number, val: string) => {
    const sanitized = val.replace(/\D/g, '');
    if (sanitized.length > 1) {
      const chars = sanitized.slice(0, 6).split('');
      const copy = [...otpDigits];
      chars.forEach((c, i) => {
        if (i < 6) copy[i] = c;
      });
      setOtpDigits(copy);
      const nextIdx = Math.min(chars.length, 5);
      otpInputsRef.current[nextIdx]?.focus();
      return;
    }

    const copy = [...otpDigits];
    copy[index] = sanitized[sanitized.length - 1] || '';
    setOtpDigits(copy);

    if (index < 5 && sanitized) {
      otpInputsRef.current[index + 1]?.focus();
    }
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !otpDigits[index] && index > 0) {
      otpInputsRef.current[index - 1]?.focus();
    }
  };

  // Verify 6-digit OTP (Twilio Verify / Mock SMS OR node_auth.js Email OTP)
  const handleVerifyOtp = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const code = otpDigits.join('');
    if (code.length !== 6) {
      setErrorMsg('Please enter all 6 digits of the verification code.');
      return;
    }

    setIsLoading(true);
    setErrorMsg(null);

    try {
      if (otpChannel === 'sms') {
        const res = await fetch('/api/v1/auth/sms/verify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            phone: activeOtpDestination,
            code,
          }),
        });

        const data = await safeReadJson(res);
        if (!res.ok || !data.success) {
          setErrorMsg(data.message || 'SMS verification failed. Please check the code.');
          return;
        }

        const token = data.token || data.data?.token;
        const verifiedUser = data.user || data.data?.user;
        if (token && verifiedUser) {
          localStorage.setItem('aegis_auth_token', token);
          localStorage.setItem('aegis_user', JSON.stringify(verifiedUser));
          onLoginSuccess(verifiedUser);
        } else {
          setErrorMsg('Verified, but session token was not returned.');
        }
        return;
      }

      // Email OTP verification via node_auth.js
      const res = await fetch('/api/v1/auth/otp/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          destination: activeOtpDestination,
          code,
        }),
      });

      const data = await safeReadJson(res);
      if (!res.ok || !data.success) {
        setErrorMsg(data.message || data.error || 'Verification failed. Please check the code.');
        return;
      }

      localStorage.setItem('aegis_auth_token', data.token);
      localStorage.setItem('aegis_user', JSON.stringify(data.user));
      onLoginSuccess(data.user);
    } catch (err: any) {
      setErrorMsg(`Verification error: ${err?.message || 'Unexpected error.'}`);
    } finally {
      setIsLoading(false);
    }
  };

  // Direct Admin Email & Key sign-in (no 2FA challenge)
  const handlePasswordLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setErrorMsg(null);
    setStatusMsg(null);

    try {
      const res = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: adminEmail.trim(),
          password: adminPassword,
        }),
      });

      const data = await safeReadJson(res);

      if (!res.ok || !data.success) {
        const challengeHint = (data as any)?.challengeRequired
          ? ' Verification challenge required before retry (Turnstile hook triggered).'
          : '';
        setErrorMsg(`${data.message || data.error || 'Authentication failed.'}${challengeHint}`);
        return;
      }

      if (data.token && data.user) {
        localStorage.setItem('aegis_auth_token', data.token);
        localStorage.setItem('aegis_user', JSON.stringify(data.user));
        onLoginSuccess(data.user);
      } else {
        setErrorMsg('Login succeeded but session data was incomplete.');
      }
    } catch (err: any) {
      setErrorMsg(err?.message || 'Login failed.');
    } finally {
      setIsLoading(false);
    }
  };

  // Firebase Google Sign-In via popup
  const handleGoogleSignIn = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    setStatusMsg(null);
    try {
      const credential = await signInWithPopup(auth, googleAuthProvider);
      await syncFirebaseUserProfile(credential.user, 'google');
      const firebaseIdToken = await credential.user.getIdToken();

      const res = await fetch('/api/v1/auth/firebase/google', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ firebaseIdToken }),
      });

      const data = await safeReadJson(res);
      if (!res.ok || !data.success) {
        setErrorMsg(data.message || data.error || 'Google Sign-In verification failed.');
        return;
      }

      localStorage.setItem('aegis_auth_token', data.token);
      localStorage.setItem('aegis_user', JSON.stringify(data.user));
      onLoginSuccess(data.user);
    } catch (err: any) {
      setErrorMsg(formatFirebasePhoneError(err));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-mesh-subtle bg-dot-grid text-[#16161D] flex flex-col items-center justify-center p-4 sm:p-6 relative overflow-hidden select-none">
      <div className="w-full max-w-md relative z-10 space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2.5">
          <div className="flex justify-center">
            <AegisGlyphLogo size={46} />
          </div>
          <div className="space-y-1">
            <p className="text-xs font-semibold text-[#B52A70] tracking-wide">Aegis Security Gateway</p>
            <h1 className="font-display text-2xl sm:text-3xl font-semibold text-[#16161D] tracking-tight text-balance">
              Welcome Back
            </h1>
            <p className="text-sm text-[#464451] max-w-xs mx-auto leading-relaxed">
              Sign in using real-time SMS or Email verification.
            </p>
          </div>
        </div>

        {/* Auth Card */}
        <div className="glass-panel rounded-3xl p-6 sm:p-8 shadow-[0_20px_50px_-15px_rgba(22,22,29,0.12)] border border-[#E5DDD0] space-y-6">
          {/* Firebase Google Sign-In */}
          <div className="space-y-3">
            <button
              type="button"
              onClick={handleGoogleSignIn}
              disabled={isLoading}
              className="w-full py-3 px-4 rounded-2xl bg-[#FFFDF9] hover:bg-[#FCECF4]/70 text-[#16161D] border border-[#D8CEC0] hover:border-[#D9468F]/60 font-semibold text-sm transition-all flex items-center justify-center space-x-2.5 disabled:opacity-50 shadow-xs active:scale-[0.99] whitespace-nowrap shrink-0"
            >
              <svg className="w-4 h-4 shrink-0" viewBox="0 0 24 24" aria-hidden="true">
                <path
                  fill="#4285F4"
                  d="M23.745 12.27c0-.7-.06-1.4-.19-2.07H12v4.51h6.6c-.29 1.52-1.14 2.82-2.4 3.68v3.05h3.88c2.27-2.09 3.665-5.17 3.665-9.17Z"
                />
                <path
                  fill="#34A853"
                  d="M12 24c3.24 0 5.95-1.08 7.93-2.91l-3.88-3.05c-1.08.72-2.45 1.16-4.05 1.16-3.12 0-5.77-2.11-6.72-4.96H1.29v3.14C3.26 21.3 7.31 24 12 24Z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.28 14.24c-.24-.72-.38-1.49-.38-2.24s.14-1.52.38-2.24V6.62H1.29C.47 8.24 0 10.06 0 12s.47 3.76 1.29 5.38l3.99-3.14Z"
                />
                <path
                  fill="#EA4335"
                  d="M12 4.75c1.77 0 3.35.61 4.6 1.8l3.42-3.42C17.95 1.19 15.24 0 12 0 7.31 0 3.26 2.7 1.29 6.62l3.99 3.14c.95-2.85 3.6-4.96 6.72-4.96Z"
                />
              </svg>
              <span>Continue with Google</span>
            </button>

            <div className="flex items-center gap-3 text-[11px] text-[#6F6C7A]">
              <div className="h-px flex-1 bg-[#E5DDD0]" />
              <span>or verify with OTP / Admin Key</span>
              <div className="h-px flex-1 bg-[#E5DDD0]" />
            </div>
          </div>

          {/* Mode Switcher Tabs */}
          <div className="flex rounded-2xl bg-[#F2ECE2] p-1 border border-[#E5DDD0] text-xs font-medium">
            <button
              type="button"
              onClick={() => {
                setAuthMode('otp');
                setErrorMsg(null);
                setStatusMsg(null);
              }}
              className={`flex-1 py-2.5 rounded-xl transition-all flex items-center justify-center space-x-2 whitespace-nowrap shrink-0 ${
                authMode === 'otp'
                  ? 'bg-[#16161D] text-[#FAF6F0] font-semibold shadow-sm'
                  : 'text-[#464451] hover:text-[#16161D]'
              }`}
            >
              <Smartphone className="w-4 h-4" />
              <span>Real-Time OTP</span>
            </button>
            <button
              type="button"
              onClick={() => {
                setAuthMode('password');
                setErrorMsg(null);
                setStatusMsg(null);
              }}
              className={`flex-1 py-2.5 rounded-xl transition-all flex items-center justify-center space-x-2 whitespace-nowrap shrink-0 ${
                authMode === 'password'
                  ? 'bg-[#16161D] text-[#FAF6F0] font-semibold shadow-sm'
                  : 'text-[#464451] hover:text-[#16161D]'
              }`}
            >
              <KeyRound className="w-4 h-4" />
              <span>Admin Key</span>
            </button>
          </div>

          {/* Error Banner */}
          {errorMsg && (
            <div className="p-3.5 rounded-2xl bg-[#FDF2F6] border border-[#D9468F]/40 text-[#88134A] text-xs flex items-start space-x-2.5">
              <AlertCircle className="w-4 h-4 text-[#D9468F] shrink-0 mt-0.5" />
              <div className="flex-1 leading-relaxed break-words">{errorMsg}</div>
            </div>
          )}

          {/* Success / Status Banner */}
          {statusMsg && (
            <div className="p-3.5 rounded-2xl bg-[#F0F7F4] border border-[#16A34A]/30 text-[#14532D] text-xs flex items-start space-x-2.5">
              <CheckCircle2 className="w-4 h-4 text-[#16A34A] shrink-0 mt-0.5" />
              <div className="flex-1 leading-relaxed">{statusMsg}</div>
            </div>
          )}

          {/* REAL-TIME OTP FLOW (MOBILE SMS VIA FIREBASE + EMAIL OTP VIA SMTP) */}
          {authMode === 'otp' && (
            <div>
              {otpStep === 'enter_destination' ? (
                <form onSubmit={handleSendOtp} className="space-y-4">
                  {/* Channel Selector: Mobile SMS vs Email */}
                  <div className="flex items-center gap-1 p-1 bg-[#F2ECE2] border border-[#E5DDD0] rounded-xl text-xs font-medium">
                    <button
                      type="button"
                      onClick={() => {
                        setOtpChannel('sms');
                        setErrorMsg(null);
                        setStatusMsg(null);
                      }}
                      className={`flex-1 py-2 rounded-lg transition-colors flex items-center justify-center space-x-1.5 whitespace-nowrap shrink-0 ${
                        otpChannel === 'sms'
                          ? 'bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] font-semibold shadow-2xs'
                          : 'text-[#464451] hover:text-[#16161D]'
                      }`}
                    >
                      <Smartphone className="w-3.5 h-3.5" />
                      <span>Mobile SMS</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setOtpChannel('email');
                        setErrorMsg(null);
                        setStatusMsg(null);
                      }}
                      className={`flex-1 py-2 rounded-lg transition-colors flex items-center justify-center space-x-1.5 whitespace-nowrap shrink-0 ${
                        otpChannel === 'email'
                          ? 'bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] font-semibold shadow-2xs'
                          : 'text-[#464451] hover:text-[#16161D]'
                      }`}
                    >
                      <Mail className="w-3.5 h-3.5" />
                      <span>Email OTP</span>
                    </button>
                  </div>

                  {otpChannel === 'sms' ? (
                    <div className="space-y-3">
                      <div className="space-y-2">
                        <label className="block text-xs font-semibold text-[#16161D]">
                          Mobile Number
                        </label>
                        <div className="flex items-center space-x-2">
                          <select
                            value={countryCode}
                            onChange={(e) => setCountryCode(e.target.value)}
                            className="bg-[#FAF6F0] border border-[#D8CEC0] rounded-2xl px-3 py-3 text-xs text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F] cursor-pointer"
                            title="Select Country Code"
                          >
                            {COUNTRY_CODES.filter(
                              (item) =>
                                smsAllowedCountries.length === 0 ||
                                smsAllowedCountries.includes(item.code)
                            ).map((item) => (
                              <option key={item.code} value={item.code} className="bg-[#FFFDF9] text-[#16161D]">
                                {item.flag} {item.code} ({item.country})
                              </option>
                            ))}
                          </select>

                          <input
                            type="tel"
                            inputMode="numeric"
                            placeholder="e.g. 9876543210"
                            value={rawPhone}
                            onChange={(e) => setRawPhone(e.target.value)}
                            autoFocus
                            required
                            className="flex-1 bg-[#FAF6F0] border border-[#D8CEC0] rounded-2xl px-4 py-3 text-sm text-[#16161D] placeholder-[#8A8794] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F] font-mono tabular-nums"
                          />
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      <label className="block text-xs font-semibold text-[#16161D]">
                        Email Address
                      </label>
                      <input
                        type="email"
                        placeholder="you@gmail.com"
                        value={otpEmail}
                        onChange={(e) => setOtpEmail(e.target.value)}
                        autoFocus
                        required
                        className="w-full bg-[#FAF6F0] border border-[#D8CEC0] rounded-2xl px-4 py-3 text-sm text-[#16161D] placeholder-[#8A8794] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F] font-mono"
                      />
                      <div className="flex items-center justify-between text-[11px] text-[#6F6C7A] pt-0.5">
                        <span>Nodemailer SMTP · node_auth.js</span>
                        <span className={emailVerified ? 'text-[#15803D] font-medium' : 'text-[#B52A70] font-medium'}>
                          {emailVerified
                            ? 'SMTP verified'
                            : emailLive
                            ? 'SMTP auth needs update'
                            : 'SMTP credentials required'}
                        </span>
                      </div>
                      {emailGatewayNotice && (
                        <p className="text-[11px] text-[#B52A70] leading-relaxed pt-1">
                          {emailGatewayNotice}
                        </p>
                      )}
                    </div>
                  )}

                  <button
                    type="submit"
                    disabled={
                      isLoading ||
                      (otpChannel === 'sms' ? !rawPhone.trim() : !otpEmail.trim())
                    }
                    className="w-full py-3.5 rounded-2xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] font-semibold text-sm transition-all flex items-center justify-center space-x-2 disabled:opacity-40 disabled:cursor-not-allowed shadow-md active:scale-[0.99] whitespace-nowrap shrink-0"
                  >
                    {isLoading ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin text-[#F472B6]" />
                        <span>{otpChannel === 'sms' ? 'Sending SMS...' : 'Sending Email...'}</span>
                      </>
                    ) : (
                      <>
                        <span>{otpChannel === 'sms' ? 'Send SMS Code' : 'Send Email Code'}</span>
                        <ArrowRight className="w-4 h-4 text-[#F472B6]" />
                      </>
                    )}
                  </button>
                </form>
              ) : (
                /* STEP 2: ENTER 6-DIGIT REAL OTP */
                <form onSubmit={handleVerifyOtp} className="space-y-5">
                  <div className="flex items-center justify-between gap-2">
                    <button
                      type="button"
                      onClick={() => {
                        setOtpStep('enter_destination');
                        setErrorMsg(null);
                        setStatusMsg(null);
                      }}
                      className="text-xs text-[#464451] hover:text-[#B52A70] flex items-center space-x-1 transition-colors whitespace-nowrap shrink-0"
                    >
                      <ChevronLeft className="w-3.5 h-3.5" />
                      <span>Change {otpChannel === 'sms' ? 'number' : 'email'}</span>
                    </button>
                    <span className="text-xs font-mono tabular-nums text-[#464451] truncate">
                      {otpChannel === 'sms' ? 'SMS' : 'Email'} · {activeOtpDestination}
                    </span>
                  </div>

                  <div className="space-y-2">
                    <label className="block text-xs font-medium text-[#464451] text-center">
                      Enter the 6-digit code sent to your {otpChannel === 'sms' ? 'phone' : 'inbox'}
                    </label>
                    <div className="flex items-center justify-between gap-2">
                      {otpDigits.map((digit, idx) => (
                        <input
                          key={idx}
                          ref={(el) => {
                            otpInputsRef.current[idx] = el;
                          }}
                          type="text"
                          inputMode="numeric"
                          maxLength={1}
                          value={digit}
                          onChange={(e) => handleOtpChange(idx, e.target.value)}
                          onKeyDown={(e) => handleKeyDown(idx, e)}
                          className="w-11 h-14 sm:w-12 sm:h-14 bg-[#FAF6F0] border border-[#D8CEC0] rounded-2xl text-center text-xl font-bold text-[#16161D] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/40 focus:border-[#D9468F] transition-all font-mono tabular-nums shadow-inner"
                        />
                      ))}
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={isLoading || otpDigits.join('').length !== 6}
                    className="w-full py-3.5 rounded-2xl bg-[#D9468F] hover:bg-[#B52A70] text-[#FFFDF9] font-semibold text-sm transition-all flex items-center justify-center space-x-2 disabled:opacity-40 disabled:cursor-not-allowed shadow-md active:scale-[0.99] whitespace-nowrap shrink-0"
                  >
                    {isLoading ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        <span>Verifying...</span>
                      </>
                    ) : (
                      <>
                        <span>Verify</span>
                        <CheckCircle2 className="w-4 h-4" />
                      </>
                    )}
                  </button>

                  <div className="text-center pt-1">
                    {cooldown > 0 ? (
                      <span className="text-xs text-[#6F6C7A] font-mono tabular-nums">
                        Resend code in <strong className="text-[#B52A70]">{cooldown}s</strong>
                      </span>
                    ) : (
                      <button
                        type="button"
                        onClick={() => handleSendOtp()}
                        disabled={isLoading}
                        className="text-xs text-[#B52A70] hover:text-[#16161D] underline font-medium transition-colors whitespace-nowrap shrink-0"
                      >
                        {otpChannel === 'sms' ? 'Resend SMS code' : 'Resend Email code'}
                      </button>
                    )}
                  </div>
                </form>
              )}
            </div>
          )}

          {/* ADMIN EMAIL & KEY FLOW */}
          {authMode === 'password' && (
            <form onSubmit={handlePasswordLogin} className="space-y-4">
              <div className="space-y-2.5">
                <label className="block text-xs font-semibold text-[#16161D]">
                  Administrator Email & Key
                </label>
                <input
                  type="email"
                  value={adminEmail}
                  onChange={(e) => setAdminEmail(e.target.value)}
                  placeholder="rajputvanshc@gmail.com"
                  required
                  className="w-full bg-[#FAF6F0] border border-[#D8CEC0] rounded-2xl px-4 py-3 text-xs text-[#16161D] placeholder-[#8A8794] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F] font-mono"
                />
                <input
                  type="password"
                  value={adminPassword}
                  onChange={(e) => setAdminPassword(e.target.value)}
                  placeholder="Admin Key"
                  required
                  className="w-full bg-[#FAF6F0] border border-[#D8CEC0] rounded-2xl px-4 py-3 text-xs text-[#16161D] placeholder-[#8A8794] focus:outline-none focus:ring-2 focus:ring-[#D9468F]/35 focus:border-[#D9468F] font-mono"
                />
              </div>

              <button
                type="submit"
                disabled={isLoading}
                className="w-full py-3.5 rounded-2xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] font-semibold text-sm transition-all flex items-center justify-center space-x-2 disabled:opacity-40 shadow-md active:scale-[0.99] whitespace-nowrap shrink-0"
              >
                {isLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin text-[#F472B6]" />
                    <span>Signing In...</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4 text-[#F472B6]" />
                    <span>Sign In</span>
                  </>
                )}
              </button>
            </form>
          )}
        </div>

        {/* Footer info */}
        <div className="text-center text-xs text-[#6F6C7A] space-y-1">
          <div className="font-medium text-[#464451]">AegisNotify Security Gateway</div>
          <div className="text-[11px] text-[#6F6C7A]">
            Firebase Phone Auth · node_auth.js · Live SMTP
          </div>
        </div>
      </div>
    </div>
  );
}
