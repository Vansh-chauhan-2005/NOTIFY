'use client';

import React, { useState } from 'react';
import {
  ShieldCheck,
  Bell,
  Lock,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  ArrowRight,
  ArrowLeft,
  Sparkles,
} from 'lucide-react';
import {
  BrowserNotificationChoice,
  saveOnboardingAndConsent,
  UserPrivacyConsentState,
} from '../lib/firebase/client';

interface OnboardingModalProps {
  userId: string;
  userEmail?: string;
  onComplete: (state: UserPrivacyConsentState) => void;
}

function readInitialBrowserNotifChoice(): BrowserNotificationChoice {
  if (typeof window === 'undefined' || !('Notification' in window)) {
    return 'unsupported';
  }
  const perm = Notification.permission;
  if (perm === 'granted' || perm === 'denied' || perm === 'default') {
    return perm;
  }
  return 'default';
}

export default function OnboardingModal({
  userId,
  userEmail,
  onComplete,
}: OnboardingModalProps) {
  const [step, setStep] = useState<1 | 2 | 3>(1);
  const [notifChoice, setNotifChoice] = useState<BrowserNotificationChoice>(
    readInitialBrowserNotifChoice
  );
  const [notifStatusMsg, setNotifStatusMsg] = useState<string | null>(null);
  const [requestingNotif, setRequestingNotif] = useState(false);

  // Consent checkboxes MUST start unchecked
  const [allowCatalogAndConnections, setAllowCatalogAndConnections] = useState(false);
  const [allowEncryptedConnectionStorage, setAllowEncryptedConnectionStorage] = useState(false);
  const [saving, setSaving] = useState(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleRequestNotificationPermission = async () => {
    if (typeof window === 'undefined' || !('Notification' in window)) {
      setNotifChoice('unsupported');
      setNotifStatusMsg(
        'This browser does not support desktop web notifications. You can still view all alerts live inside your Aegis inbox.'
      );
      return;
    }

    setRequestingNotif(true);
    setNotifStatusMsg(null);
    try {
      const result = await Notification.requestPermission();
      if (result === 'granted') {
        setNotifChoice('granted');
        setNotifStatusMsg('Browser notifications enabled. Critical and incoming alerts can appear on this device.');
      } else if (result === 'denied') {
        setNotifChoice('denied');
        setNotifStatusMsg(
          'Notifications were blocked by the browser. You can still use Aegis normally and enable notifications later in browser settings.'
        );
      } else {
        setNotifChoice('default');
        setNotifStatusMsg(
          'Permission prompt was dismissed without deciding. You can try again anytime from Settings → Permissions & Privacy.'
        );
      }
    } catch {
      setNotifChoice('unsupported');
      setNotifStatusMsg('Unable to request notification permission in this browser context.');
    } finally {
      setRequestingNotif(false);
    }
  };

  const handleSkipNotifications = () => {
    if (notifChoice !== 'granted') {
      setNotifChoice('skipped');
    }
    setNotifStatusMsg('Skipped for now. You can turn on browser notifications later in Settings.');
    setStep(3);
  };

  const logConsentTelemetry = async (granted: boolean, details: string) => {
    try {
      const token =
        typeof window !== 'undefined' ? window.localStorage.getItem('aegis_auth_token') : null;
      if (!token) return;
      await fetch('/api/v1/telemetry/client-event', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          eventType: granted ? 'CONSENT_GRANTED' : 'CONSENT_DENIED',
          result: granted ? 'success' : 'blocked',
          details,
        }),
      });
    } catch {
      // Telemetry log failure must not block onboarding completion
    }
  };

  const finishOnboarding = async (grantAll: boolean) => {
    setSaving(true);
    setErrorMsg(null);
    try {
      const allowCatalog = grantAll ? allowCatalogAndConnections : false;
      const allowEncrypted = grantAll ? allowEncryptedConnectionStorage : false;
      const state = await saveOnboardingAndConsent(userId, {
        allowCatalogAndConnections: allowCatalog,
        allowEncryptedConnectionStorage: allowEncrypted,
        browserNotificationsChoice: notifChoice,
        revoked: !allowCatalog || !allowEncrypted,
      });

      const granted = state.consentGranted;
      await logConsentTelemetry(
        granted,
        granted
          ? `User granted catalog & encrypted storage consent (notifications=${notifChoice}).`
          : `User completed onboarding without full catalog consent (notifications=${notifChoice}).`
      );

      onComplete(state);
    } catch (err: any) {
      setErrorMsg(err?.message || 'Could not save your privacy choices. Please try again.');
    } finally {
      setSaving(false);
    }
  };

  const bothChecked = allowCatalogAndConnections && allowEncryptedConnectionStorage;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-[#16161D]/70 backdrop-blur-md p-4 overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="onboarding-modal-title"
    >
      <div className="w-full max-w-2xl rounded-3xl bg-[#FFFDF9] border border-[#E5DDD0] shadow-2xl overflow-hidden my-auto">
        {/* Progress Header */}
        <div className="px-6 py-5 bg-[#FAF6F0] border-b border-[#E5DDD0] flex items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-2xl bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] flex items-center justify-center shrink-0">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h2
                id="onboarding-modal-title"
                className="font-display text-lg font-semibold text-[#16161D]"
              >
                Welcome to AegisNotify
              </h2>
              <p className="text-xs text-[#6F6C7A]">
                {userEmail ? `Signed in as ${userEmail} · ` : ''}Quick privacy &amp; permission setup (Step {step} of 3)
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-1.5 shrink-0">
            {[1, 2, 3].map((s) => (
              <span
                key={s}
                className={`h-2 rounded-full transition-all ${
                  s === step
                    ? 'w-7 bg-[#D9468F]'
                    : s < step
                    ? 'w-3 bg-[#16161D]'
                    : 'w-3 bg-[#D8CEC0]'
                }`}
              />
            ))}
          </div>
        </div>

        {/* Body */}
        <div className="p-6 sm:p-8 space-y-6">
          {step === 1 && (
            <div className="space-y-5">
              <div className="space-y-2">
                <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] text-[11px] font-semibold">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Step 1 · What this app does</span>
                </span>
                <h3 className="font-display text-2xl font-semibold text-[#16161D]">
                  Security-first notifications, with zero hidden scanning
                </h3>
                <p className="text-sm text-[#464451] leading-relaxed">
                  AegisNotify helps you receive, verify, and prioritize alerts from the apps you choose to connect. Here is exactly what data it handles:
                </p>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
                <div className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 space-y-1.5">
                  <p className="text-xs font-semibold text-[#16161D]">
                    1. Your connected webhooks &amp; bots
                  </p>
                  <p className="text-xs text-[#6F6C7A] leading-relaxed">
                    Tokens and signing secrets are encrypted on the server and never exposed back to the browser after setup.
                  </p>
                </div>
                <div className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 space-y-1.5">
                  <p className="text-xs font-semibold text-[#16161D]">
                    2. Honest browser limits
                  </p>
                  <p className="text-xs text-[#6F6C7A] leading-relaxed">
                    Web browsers cannot read what apps are installed on your device. We never fake detection or scan outside our 30-app catalog.
                  </p>
                </div>
              </div>

              <div className="flex items-center justify-end pt-2">
                <button
                  type="button"
                  onClick={() => setStep(2)}
                  className="px-5 py-2.5 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-xs font-semibold flex items-center space-x-2 transition-colors whitespace-nowrap"
                >
                  <span>Continue</span>
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}

          {step === 2 && (
            <div className="space-y-5">
              <div className="space-y-2">
                <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] text-[11px] font-semibold">
                  <Bell className="w-3.5 h-3.5" />
                  <span>Step 2 · Browser Notifications</span>
                </span>
                <h3 className="font-display text-2xl font-semibold text-[#16161D]">
                  Get instant alerts when an event arrives
                </h3>
                <p className="text-sm text-[#464451] leading-relaxed">
                  If you allow browser notifications, AegisNotify can show a desktop/mobile alert right away when a verified notification arrives in your live inbox. We never ask without you clicking below.
                </p>
              </div>

              <div className="rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div className="flex items-center space-x-3">
                  {notifChoice === 'granted' ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0" />
                  ) : notifChoice === 'denied' ? (
                    <XCircle className="w-5 h-5 text-red-600 shrink-0" />
                  ) : (
                    <Bell className="w-5 h-5 text-[#D9468F] shrink-0" />
                  )}
                  <div>
                    <p className="text-xs font-semibold text-[#16161D]">
                      Current Permission:{' '}
                      <span className="font-mono-tech uppercase">{notifChoice}</span>
                    </p>
                    <p className="text-[11px] text-[#6F6C7A]">
                      {notifStatusMsg || 'Click "Allow notifications" to trigger the browser prompt.'}
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => void handleRequestNotificationPermission()}
                  disabled={requestingNotif || notifChoice === 'granted'}
                  className="px-4 py-2 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] disabled:opacity-60 text-[#FFFDF9] text-xs font-semibold transition-colors whitespace-nowrap shrink-0"
                >
                  {notifChoice === 'granted'
                    ? 'Notifications Allowed'
                    : requestingNotif
                    ? 'Requesting...'
                    : 'Allow notifications'}
                </button>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setStep(1)}
                  className="px-4 py-2 rounded-xl border border-[#D8CEC0] text-[#464451] hover:bg-[#F2ECE2] text-xs font-semibold flex items-center space-x-1.5 whitespace-nowrap"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Back</span>
                </button>

                <div className="flex items-center space-x-2.5">
                  <button
                    type="button"
                    onClick={handleSkipNotifications}
                    className="px-4 py-2 rounded-xl border border-[#D8CEC0] text-[#464451] hover:bg-[#F2ECE2] text-xs font-semibold whitespace-nowrap"
                  >
                    Skip for now
                  </button>
                  <button
                    type="button"
                    onClick={() => setStep(3)}
                    className="px-5 py-2.5 rounded-xl bg-[#16161D] hover:bg-[#2A2935] text-[#FAF6F0] text-xs font-semibold flex items-center space-x-2 whitespace-nowrap"
                  >
                    <span>Next</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          )}

          {step === 3 && (
            <div className="space-y-5">
              <div className="space-y-2">
                <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-[#FCECF4] text-[#B52A70] border border-[#F2C4DC] text-[11px] font-semibold">
                  <Lock className="w-3.5 h-3.5" />
                  <span>Step 3 · Explicit Privacy Consent</span>
                </span>
                <h3 className="font-display text-2xl font-semibold text-[#16161D]">
                  Choose what features to enable
                </h3>
                <p className="text-sm text-[#464451] leading-relaxed">
                  Nothing is pre-checked. You can revoke consent or delete your connection data anytime inside Settings → Permissions &amp; Privacy.
                </p>
              </div>

              <div className="space-y-3">
                <label className="flex items-start space-x-3 p-4 rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] cursor-pointer hover:border-[#D9468F]/50 transition-colors">
                  <input
                    type="checkbox"
                    checked={allowCatalogAndConnections}
                    onChange={(e) => setAllowCatalogAndConnections(e.target.checked)}
                    className="mt-0.5 h-4 w-4 rounded border-[#D8CEC0] text-[#D9468F] focus:ring-[#D9468F]"
                  />
                  <div>
                    <span className="block text-xs font-semibold text-[#16161D]">
                      Allow app catalog and connections
                    </span>
                    <span className="block text-[11px] text-[#6F6C7A] mt-0.5">
                      Lets you browse the 30-app catalog, record which apps you use, and connect supported webhooks or bots.
                    </span>
                  </div>
                </label>

                <label className="flex items-start space-x-3 p-4 rounded-2xl bg-[#FAF6F0] border border-[#E5DDD0] cursor-pointer hover:border-[#D9468F]/50 transition-colors">
                  <input
                    type="checkbox"
                    checked={allowEncryptedConnectionStorage}
                    onChange={(e) => setAllowEncryptedConnectionStorage(e.target.checked)}
                    className="mt-0.5 h-4 w-4 rounded border-[#D8CEC0] text-[#D9468F] focus:ring-[#D9468F]"
                  />
                  <div>
                    <span className="block text-xs font-semibold text-[#16161D]">
                      Allow storing connection settings (encrypted)
                    </span>
                    <span className="block text-[11px] text-[#6F6C7A] mt-0.5">
                      Saves your connection secrets encrypted with AES-256-GCM on the server and your catalog choices in your profile.
                    </span>
                  </div>
                </label>
              </div>

              {!bothChecked && (
                <div className="rounded-xl bg-amber-50 border border-amber-200 px-3.5 py-2.5 flex items-start space-x-2 text-xs text-amber-900">
                  <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-amber-600" />
                  <span>
                    Check both boxes above to activate App Catalog &amp; Connections, or choose &quot;Continue without catalog&quot; to use login and inbox features only.
                  </span>
                </div>
              )}

              {errorMsg && (
                <div className="rounded-xl bg-red-50 border border-red-200 px-3.5 py-2.5 text-xs text-red-700">
                  {errorMsg}
                </div>
              )}

              <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setStep(2)}
                  disabled={saving}
                  className="px-4 py-2 rounded-xl border border-[#D8CEC0] text-[#464451] hover:bg-[#F2ECE2] text-xs font-semibold flex items-center space-x-1.5 whitespace-nowrap"
                >
                  <ArrowLeft className="w-3.5 h-3.5" />
                  <span>Back</span>
                </button>

                <div className="flex flex-wrap items-center gap-2.5">
                  <button
                    type="button"
                    onClick={() => void finishOnboarding(false)}
                    disabled={saving}
                    className="px-4 py-2 rounded-xl border border-[#D8CEC0] text-[#464451] hover:bg-[#F2ECE2] text-xs font-semibold whitespace-nowrap disabled:opacity-50"
                  >
                    Continue without catalog
                  </button>
                  <button
                    type="button"
                    onClick={() => void finishOnboarding(true)}
                    disabled={saving || !bothChecked}
                    className="px-5 py-2.5 rounded-xl bg-[#D9468F] hover:bg-[#B52A70] disabled:opacity-45 text-[#FFFDF9] text-xs font-semibold flex items-center space-x-2 whitespace-nowrap transition-colors"
                  >
                    <CheckCircle2 className="w-4 h-4" />
                    <span>{saving ? 'Saving...' : 'Save Consent & Enter App'}</span>
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
