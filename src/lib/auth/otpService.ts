import { isFast2SmsConfigured } from '../integrations/fast2smsService.js';
import {
  generateAndSendOtp,
  verifyOtp,
  authenticateWithOtp,
  authenticateWithFirebasePhone,
  verifyFirebasePhoneIdToken,
  getFirebaseProjectId,
  getOtpAuditLogs,
  getOtpSecurityPolicy,
} from './node_auth.js';

export function isSmsConfigured(): boolean {
  return Boolean(getFirebaseProjectId()) || isFast2SmsConfigured();
}

/**
 * Dispatch verification OTP code via node_auth.js (strict live Nodemailer / SMS)
 */
export async function sendOtpToPhone(
  targetDestination: string,
  options?: { purpose?: 'LOGIN_OTP' | 'LOGIN_2FA'; auditContext?: { ip?: string; userAgent?: string } }
) {
  return generateAndSendOtp(targetDestination, {
    purpose: options?.purpose || 'LOGIN_OTP',
    auditContext: options?.auditContext,
  });
}

/**
 * Verify a 6-digit OTP code via node_auth.js
 */
export function verifyOtpForPhone(
  destination: string,
  inputCode: string,
  options?: { purpose?: 'LOGIN_OTP' | 'LOGIN_2FA'; auditContext?: { ip?: string; userAgent?: string } }
) {
  return verifyOtp(destination, inputCode, options);
}

export {
  generateAndSendOtp,
  verifyOtp,
  authenticateWithOtp,
  authenticateWithFirebasePhone,
  verifyFirebasePhoneIdToken,
  getFirebaseProjectId,
  getOtpAuditLogs,
  getOtpSecurityPolicy,
};
