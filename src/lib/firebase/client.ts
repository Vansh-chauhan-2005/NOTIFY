import { initializeApp, getApps } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  RecaptchaVerifier,
  signInWithPhoneNumber,
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  setPersistence,
  browserLocalPersistence,
  browserSessionPersistence,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
  updateProfile,
  EmailAuthProvider,
  reauthenticateWithCredential,
  reauthenticateWithPopup,
  linkWithCredential,
  linkWithPopup,
  unlink,
  updateEmail,
  deleteUser,
  getAdditionalUserInfo,
  getMultiFactorResolver,
  multiFactor,
  TotpMultiFactorGenerator,
  ConfirmationResult,
  User,
} from 'firebase/auth';
import {
  getFirestore,
  doc,
  collection,
  query,
  where,
  orderBy,
  limit,
  getDocFromServer,
  getDocs,
  setDoc,
  updateDoc,
  deleteDoc,
  onSnapshot,
  serverTimestamp,
  Timestamp,
} from 'firebase/firestore';
import firebaseConfig from '../../../firebase-applet-config.json';

const app = getApps().length > 0 ? getApps()[0] : initializeApp(firebaseConfig);

export const auth = getAuth(app);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const firebaseProjectId = firebaseConfig.projectId;
export const googleAuthProvider = new GoogleAuthProvider();
googleAuthProvider.setCustomParameters({ prompt: 'select_account' });

export {
  app,
  RecaptchaVerifier,
  signInWithPhoneNumber,
  signInWithPopup,
  signOut,
  onAuthStateChanged,
  setPersistence,
  browserLocalPersistence,
  browserSessionPersistence,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
  updateProfile,
  EmailAuthProvider,
  reauthenticateWithCredential,
  reauthenticateWithPopup,
  linkWithCredential,
  linkWithPopup,
  unlink,
  updateEmail,
  deleteUser,
  getAdditionalUserInfo,
  getMultiFactorResolver,
  multiFactor,
  TotpMultiFactorGenerator,
};
export type { ConfirmationResult, User };

export enum OperationType {
  CREATE = 'create',
  UPDATE = 'update',
  DELETE = 'delete',
  LIST = 'list',
  GET = 'get',
  WRITE = 'write',
}

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationType;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(
  error: unknown,
  operationType: OperationType,
  path: string | null
): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error:', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

// Validate Firestore connection on module initialization
async function testConnection() {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
    }
  }
}
void testConnection();

export type AuthProviderKind = 'google' | 'phone' | 'email_otp' | 'password_2fa' | 'password';

/**
 * Persist or refresh the authenticated user's profile in Firestore under /users/{uid}.
 */
export async function syncFirebaseUserProfile(user: User, authProvider: AuthProviderKind = 'google') {
  const path = `users/${user.uid}`;
  const cleanDisplayName = user.displayName ? user.displayName.trim().slice(0, 120) : undefined;
  const cleanPhotoUrl = user.photoURL ? user.photoURL.trim().slice(0, 500) : undefined;
  const cleanEmail = user.email ? user.email.trim().slice(0, 254) : undefined;
  const cleanPhone =
    user.phoneNumber && /^\+?[0-9]{8,20}$/.test(user.phoneNumber)
      ? user.phoneNumber.slice(0, 24)
      : undefined;

  try {
    const userRef = doc(db, 'users', user.uid);
    const existingSnap = await getDocFromServer(userRef).catch(() => null);
    if (existingSnap && existingSnap.exists()) {
      await updateDoc(userRef, {
        ...(cleanPhone ? { phoneNumber: cleanPhone } : {}),
        ...(cleanEmail ? { email: cleanEmail } : {}),
        ...(cleanDisplayName ? { displayName: cleanDisplayName } : {}),
        ...(cleanPhotoUrl ? { photoURL: cleanPhotoUrl } : {}),
        authProvider,
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(userRef, {
        uid: user.uid,
        ...(cleanPhone ? { phoneNumber: cleanPhone } : {}),
        ...(cleanEmail ? { email: cleanEmail } : {}),
        ...(cleanDisplayName ? { displayName: cleanDisplayName } : {}),
        ...(cleanPhotoUrl ? { photoURL: cleanPhotoUrl } : {}),
        role: 'USER',
        authProvider,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

const ensuredProfilePromises = new Map<string, Promise<boolean>>();

/**
 * Guarantee the parent /users/{uid} document exists before writing to any /users/{uid}/* subcollection
 * protected by hasUserProfile(userId) in firestore.rules.
 */
export async function ensureUserProfileInFirestore(uid: string): Promise<boolean> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return false;

  const existingPromise = ensuredProfilePromises.get(uid);
  if (existingPromise) {
    return existingPromise;
  }

  const run = (async (): Promise<boolean> => {
    const user = auth.currentUser;
    if (!user || user.uid !== uid) return false;
    const path = `users/${uid}`;
    try {
      const userRef = doc(db, 'users', uid);
      const snap = await getDocFromServer(userRef).catch(() => null);
      if (snap && snap.exists() && snap.data()?.uid === uid) {
        return true;
      }

      const providerIds = user.providerData?.map((p) => p.providerId) || [];
      const detectedProvider: AuthProviderKind = providerIds.includes('google.com')
        ? 'google'
        : providerIds.includes('phone')
        ? 'phone'
        : 'password';
      const cleanEmail = user.email ? user.email.trim().slice(0, 254) : '';
      const cleanDisplayName = user.displayName ? user.displayName.trim().slice(0, 120) : '';
      const cleanPhotoUrl =
        user.photoURL && user.photoURL.trim().length <= 500 ? user.photoURL.trim() : '';
      const cleanPhone =
        user.phoneNumber && /^\+?[0-9]{8,20}$/.test(user.phoneNumber)
          ? user.phoneNumber.slice(0, 24)
          : '';

      if (snap && snap.exists()) {
        await updateDoc(userRef, {
          ...(cleanEmail ? { email: cleanEmail } : {}),
          ...(cleanDisplayName ? { displayName: cleanDisplayName } : {}),
          ...(cleanPhotoUrl ? { photoURL: cleanPhotoUrl } : {}),
          ...(cleanPhone ? { phoneNumber: cleanPhone } : {}),
          emailVerified: Boolean(user.emailVerified),
          updatedAt: serverTimestamp(),
        });
      } else {
        await setDoc(userRef, {
          uid,
          role: 'USER',
          authProvider: detectedProvider,
          ...(cleanPhone ? { phoneNumber: cleanPhone } : {}),
          ...(cleanEmail ? { email: cleanEmail } : {}),
          ...(cleanDisplayName ? { displayName: cleanDisplayName } : {}),
          ...(cleanPhotoUrl ? { photoURL: cleanPhotoUrl } : {}),
          emailVerified: Boolean(user.emailVerified),
          createdAt: serverTimestamp(),
          updatedAt: serverTimestamp(),
        });
      }
      return true;
    } catch (error) {
      ensuredProfilePromises.delete(uid);
      try {
        handleFirestoreError(error, OperationType.WRITE, path);
      } catch {
        return false;
      }
    }
  })();

  ensuredProfilePromises.set(uid, run);
  const ok = await run;
  if (!ok) {
    ensuredProfilePromises.delete(uid);
  }
  return ok;
}

export interface VerifiedPhoneFirestoreStatus {
  phoneVerified: boolean;
  maskedPhone?: string;
  phoneHash?: string;
}

export async function linkVerifiedPhoneInFirestore(
  uid: string,
  maskedPhone: string,
  phoneHash: string
): Promise<void> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return;
  const path = `users/${uid}`;
  try {
    const userRef = doc(db, 'users', uid);
    const existingSnap = await getDocFromServer(userRef).catch(() => null);
    if (existingSnap && existingSnap.exists()) {
      await updateDoc(userRef, {
        phoneVerified: true,
        maskedPhone: maskedPhone.slice(0, 24),
        phoneHash: phoneHash.slice(0, 64),
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(userRef, {
        uid,
        ...(auth.currentUser.email ? { email: auth.currentUser.email.trim().slice(0, 254) } : {}),
        ...(auth.currentUser.displayName
          ? { displayName: auth.currentUser.displayName.trim().slice(0, 120) }
          : {}),
        role: 'USER',
        authProvider: 'google',
        phoneVerified: true,
        maskedPhone: maskedPhone.slice(0, 24),
        phoneHash: phoneHash.slice(0, 64),
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function loadUserPhoneStatusFromFirestore(
  uid: string
): Promise<VerifiedPhoneFirestoreStatus | null> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return null;
  const path = `users/${uid}`;
  try {
    const snap = await getDocFromServer(doc(db, 'users', uid));
    if (!snap.exists()) return null;
    const data = snap.data();
    return {
      phoneVerified: Boolean(data.phoneVerified),
      ...(data.maskedPhone ? { maskedPhone: String(data.maskedPhone) } : {}),
      ...(data.phoneHash ? { phoneHash: String(data.phoneHash) } : {}),
    };
  } catch {
    return null;
  }
}

export interface PersistedUserPreferences {
  dndEnabled: boolean;
  quietHoursStart: string;
  quietHoursEnd: string;
  preferredChannel: 'WEBSOCKET' | 'EMAIL' | 'SMS' | 'WEBPUSH';
  minPriorityThreshold: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  audioAlertsEnabled: boolean;
  allowCriticalBypassQuietHours?: boolean;
  optOutPush?: boolean;
  optOutSms?: boolean;
  optOutEmail?: boolean;
}

const DEFAULT_PREFERENCES: PersistedUserPreferences = {
  dndEnabled: false,
  quietHoursStart: '22:00',
  quietHoursEnd: '07:00',
  preferredChannel: 'WEBSOCKET',
  minPriorityThreshold: 'LOW',
  audioAlertsEnabled: true,
  allowCriticalBypassQuietHours: true,
  optOutPush: false,
  optOutSms: false,
  optOutEmail: false,
};

function sanitizeTimeHHMM(val: string, fallback: string): string {
  return /^([01]\d|2[0-3]):[0-5]\d$/.test(val) ? val : fallback;
}

export async function loadUserPreferencesFromFirestore(
  uid: string
): Promise<PersistedUserPreferences | null> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return null;
  const path = `users/${uid}/preferences/settings`;
  try {
    const snap = await getDocFromServer(doc(db, 'users', uid, 'preferences', 'settings'));
    if (!snap.exists()) return null;
    const data = snap.data();
    return {
      dndEnabled: Boolean(data.dndEnabled),
      quietHoursStart: sanitizeTimeHHMM(String(data.quietHoursStart || ''), '22:00'),
      quietHoursEnd: sanitizeTimeHHMM(String(data.quietHoursEnd || ''), '07:00'),
      preferredChannel: ['WEBSOCKET', 'EMAIL', 'SMS', 'WEBPUSH'].includes(data.preferredChannel)
        ? data.preferredChannel
        : 'WEBSOCKET',
      minPriorityThreshold: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(data.minPriorityThreshold)
        ? data.minPriorityThreshold
        : 'LOW',
      audioAlertsEnabled: typeof data.audioAlertsEnabled === 'boolean' ? data.audioAlertsEnabled : true,
      allowCriticalBypassQuietHours:
        typeof data.allowCriticalBypassQuietHours === 'boolean'
          ? data.allowCriticalBypassQuietHours
          : true,
      optOutPush: Boolean(data.optOutPush),
      optOutSms: Boolean(data.optOutSms),
      optOutEmail: Boolean(data.optOutEmail),
    };
  } catch (error) {
    handleFirestoreError(error, OperationType.GET, path);
  }
}

export async function saveUserPreferencesToFirestore(
  uid: string,
  prefs: Partial<PersistedUserPreferences>
): Promise<void> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return;
  const path = `users/${uid}/preferences/settings`;
  try {
    await ensureUserProfileInFirestore(uid);
    const prefRef = doc(db, 'users', uid, 'preferences', 'settings');
    const existingSnap = await getDocFromServer(prefRef).catch(() => null);
    const merged: PersistedUserPreferences = {
      ...DEFAULT_PREFERENCES,
      ...(existingSnap?.exists() ? (existingSnap.data() as Partial<PersistedUserPreferences>) : {}),
      ...prefs,
    };
    const payload = {
      dndEnabled: Boolean(merged.dndEnabled),
      quietHoursStart: sanitizeTimeHHMM(merged.quietHoursStart, '22:00'),
      quietHoursEnd: sanitizeTimeHHMM(merged.quietHoursEnd, '07:00'),
      preferredChannel: (['WEBSOCKET', 'EMAIL', 'SMS', 'WEBPUSH'].includes(merged.preferredChannel)
        ? merged.preferredChannel
        : 'WEBSOCKET') as PersistedUserPreferences['preferredChannel'],
      minPriorityThreshold: (['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(merged.minPriorityThreshold)
        ? merged.minPriorityThreshold
        : 'LOW') as PersistedUserPreferences['minPriorityThreshold'],
      audioAlertsEnabled: Boolean(merged.audioAlertsEnabled),
      allowCriticalBypassQuietHours: Boolean(merged.allowCriticalBypassQuietHours),
      optOutPush: Boolean(merged.optOutPush),
      optOutSms: Boolean(merged.optOutSms),
      optOutEmail: Boolean(merged.optOutEmail),
    };

    if (existingSnap && existingSnap.exists()) {
      await updateDoc(prefRef, {
        ...payload,
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(prefRef, {
        uid,
        ...payload,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export type ChatRolePreset =
  | 'sentinel_analyst'
  | 'incident_responder'
  | 'policy_advisor'
  | 'fast_triage'
  | 'custom';

export type GeminiChatModel = 'gemini-4-hydrogen' | 'gemini-3.1-flash-lite';

export interface FirestoreChatThread {
  id: string;
  uid: string;
  title: string;
  rolePreset: ChatRolePreset;
  systemInstruction: string;
  model: GeminiChatModel;
  messageCount: number;
  updatedAt?: Date;
}

export interface FirestoreChatMessage {
  id: string;
  uid: string;
  threadId: string;
  role: 'user' | 'model';
  text: string;
  model: GeminiChatModel;
  createdAt?: Date;
}

function makeSafeFirestoreId(prefix: string): string {
  const rand =
    typeof crypto !== 'undefined' && crypto.randomUUID
      ? crypto.randomUUID().replace(/-/g, '').slice(0, 12)
      : Math.random().toString(36).slice(2, 10);
  return `${prefix}_${Date.now()}_${rand}`.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 120);
}

export function subscribeChatThreads(
  uid: string,
  onData: (threads: FirestoreChatThread[]) => void,
  onError?: (err: Error) => void
) {
  const path = `users/${uid}/chatThreads`;
  const q = query(
    collection(db, 'users', uid, 'chatThreads'),
    where('uid', '==', uid),
    orderBy('updatedAt', 'desc'),
    limit(25)
  );
  return onSnapshot(
    q,
    (snap) => {
      const threads: FirestoreChatThread[] = snap.docs.map((d) => {
        const data = d.data();
        return {
          id: d.id,
          uid: String(data.uid),
          title: String(data.title || 'New Chat'),
          rolePreset: (data.rolePreset || 'sentinel_analyst') as ChatRolePreset,
          systemInstruction: String(data.systemInstruction || ''),
          model: (data.model || 'gemini-4-hydrogen') as GeminiChatModel,
          messageCount: Number(data.messageCount || 0),
          updatedAt:
            data.updatedAt instanceof Timestamp ? data.updatedAt.toDate() : new Date(),
        };
      });
      onData(threads);
    },
    (error) => {
      try {
        handleFirestoreError(error, OperationType.LIST, path);
      } catch (wrapped: any) {
        onError?.(wrapped);
      }
    }
  );
}

export async function createChatThreadInFirestore(
  uid: string,
  params: {
    title: string;
    rolePreset: ChatRolePreset;
    systemInstruction: string;
    model: GeminiChatModel;
  }
): Promise<string> {
  const threadId = makeSafeFirestoreId('thr');
  const path = `users/${uid}/chatThreads/${threadId}`;
  try {
    await setDoc(doc(db, 'users', uid, 'chatThreads', threadId), {
      uid,
      title: (params.title.trim() || 'New Security Chat').slice(0, 120),
      rolePreset: params.rolePreset,
      systemInstruction: (params.systemInstruction.trim() || 'You are a helpful security assistant.').slice(0, 2000),
      model: params.model,
      messageCount: 0,
      createdAt: serverTimestamp(),
      updatedAt: serverTimestamp(),
    });
    return threadId;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function updateChatThreadInFirestore(
  uid: string,
  threadId: string,
  updates: Partial<{
    title: string;
    rolePreset: ChatRolePreset;
    systemInstruction: string;
    model: GeminiChatModel;
    messageCount: number;
  }>
): Promise<void> {
  const path = `users/${uid}/chatThreads/${threadId}`;
  try {
    const clean: Record<string, any> = { updatedAt: serverTimestamp() };
    if (updates.title !== undefined) clean.title = (updates.title.trim() || 'Chat').slice(0, 120);
    if (updates.rolePreset !== undefined) clean.rolePreset = updates.rolePreset;
    if (updates.systemInstruction !== undefined) {
      clean.systemInstruction = (updates.systemInstruction.trim() || 'You are a helpful assistant.').slice(0, 2000);
    }
    if (updates.model !== undefined) clean.model = updates.model;
    if (updates.messageCount !== undefined) {
      clean.messageCount = Math.min(500, Math.max(0, Math.floor(updates.messageCount)));
    }
    await updateDoc(doc(db, 'users', uid, 'chatThreads', threadId), clean);
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}

export async function deleteChatThreadInFirestore(uid: string, threadId: string): Promise<void> {
  const path = `users/${uid}/chatThreads/${threadId}`;
  try {
    await deleteDoc(doc(db, 'users', uid, 'chatThreads', threadId));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}

export function subscribeChatMessages(
  uid: string,
  threadId: string,
  onData: (messages: FirestoreChatMessage[]) => void,
  onError?: (err: Error) => void
) {
  const path = `users/${uid}/chatThreads/${threadId}/messages`;
  const q = query(
    collection(db, 'users', uid, 'chatThreads', threadId, 'messages'),
    where('uid', '==', uid),
    orderBy('createdAt', 'asc'),
    limit(200)
  );
  return onSnapshot(
    q,
    (snap) => {
      const msgs: FirestoreChatMessage[] = snap.docs.map((d) => {
        const data = d.data();
        return {
          id: d.id,
          uid: String(data.uid),
          threadId: String(data.threadId),
          role: (data.role === 'model' ? 'model' : 'user') as 'user' | 'model',
          text: String(data.text || ''),
          model: (data.model || 'gemini-4-hydrogen') as GeminiChatModel,
          createdAt:
            data.createdAt instanceof Timestamp ? data.createdAt.toDate() : new Date(),
        };
      });
      onData(msgs);
    },
    (error) => {
      try {
        handleFirestoreError(error, OperationType.LIST, path);
      } catch (wrapped: any) {
        onError?.(wrapped);
      }
    }
  );
}

export async function addChatMessageInFirestore(
  uid: string,
  threadId: string,
  params: {
    role: 'user' | 'model';
    text: string;
    model: GeminiChatModel;
  }
): Promise<string> {
  const messageId = makeSafeFirestoreId('msg');
  const path = `users/${uid}/chatThreads/${threadId}/messages/${messageId}`;
  try {
    await setDoc(doc(db, 'users', uid, 'chatThreads', threadId, 'messages', messageId), {
      uid,
      threadId,
      role: params.role,
      text: params.text.trim().slice(0, 20000) || '(empty)',
      model: params.model,
      createdAt: serverTimestamp(),
    });
    return messageId;
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

/**
 * Translate Firebase Auth error codes into clear, actionable guidance.
 */
export function formatFirebasePhoneError(err: any): string {
  const code = String(err?.code || '');
  const rawMessage = String(err?.message || 'Firebase Authentication failed.');

  switch (code) {
    case 'auth/operation-not-allowed':
      return `This sign-in method is disabled for Firebase project "${firebaseConfig.projectId}". Enable it in Firebase Console (Authentication → Sign-in method).`;
    case 'auth/unauthorized-domain':
      return `Domain "${typeof window !== 'undefined' ? window.location.hostname : 'current host'}" is not authorized in Firebase Console (Authentication → Settings → Authorized domains).`;
    case 'auth/popup-closed-by-user':
      return 'Google Sign-In popup was closed before completing sign-in.';
    case 'auth/popup-blocked':
      return 'Sign-In popup was blocked by the browser. Please allow popups for this site and try again.';
    case 'auth/captcha-check-failed':
    case 'auth/invalid-app-credential':
      return 'reCAPTCHA verification failed. Please complete the reCAPTCHA challenge again and ensure this domain is in Firebase Authorized domains.';
    case 'auth/billing-not-enabled':
      return `Firebase SMS delivery requires billing enabled on project "${firebaseConfig.projectId}" (or configure a Firebase Console test phone number).`;
    case 'auth/invalid-phone-number':
      return 'Invalid phone number. Enter a valid international number with country code (e.g., +919876543210).';
    case 'auth/too-many-requests':
      return 'Too many requests from this device or account. Please wait before trying again.';
    case 'auth/invalid-verification-code':
      return 'Incorrect 6-digit SMS verification code. Please check your phone messages and try again.';
    case 'auth/code-expired':
    case 'auth/session-expired':
      return 'The SMS verification code has expired. Please request a new OTP.';
    case 'auth/missing-verification-code':
      return 'Please enter the 6-digit SMS verification code.';
    default:
      return rawMessage;
  }
}

export const PRIVACY_POLICY_VERSION = '2026.11';
export const CONSENT_VERSION = 'v1';

export type BrowserNotificationChoice =
  | 'granted'
  | 'denied'
  | 'default'
  | 'skipped'
  | 'unsupported';

export interface UserPrivacyConsentState {
  onboardingCompleted: boolean;
  consentGranted: boolean;
  policyVersion: string;
  consentVersion: string;
  allowCatalogAndConnections: boolean;
  allowEncryptedConnectionStorage: boolean;
  browserNotificationsChoice: BrowserNotificationChoice;
  revoked: boolean;
  updatedAt: string;
}

export interface FirestoreAppCatalogStateRecord {
  appId: string;
  status: 'Detected' | 'Launchable' | 'Marked by you' | 'Unknown';
  markedByUser: boolean;
  deepLinkConfirmed: 'yes' | 'no' | 'untested';
  relatedAppDetected: boolean;
  updatedAt: string;
}

const LOCAL_CONSENT_PREFIX = 'aegis_privacy_consent_v1_';

function safeLocalConsentKey(userId: string): string {
  return `${LOCAL_CONSENT_PREFIX}${(userId || 'guest').replace(/[^a-zA-Z0-9_-]/g, '_')}`;
}

export function loadLocalPrivacyConsent(userId: string): UserPrivacyConsentState | null {
  if (typeof window === 'undefined') return null;
  try {
    const raw = window.localStorage.getItem(safeLocalConsentKey(userId));
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return null;
    return parsed as UserPrivacyConsentState;
  } catch {
    return null;
  }
}

export function saveLocalPrivacyConsent(userId: string, state: UserPrivacyConsentState): void {
  if (typeof window === 'undefined') return;
  try {
    window.localStorage.setItem(safeLocalConsentKey(userId), JSON.stringify(state));
  } catch {
    // Non-fatal
  }
}

export async function loadOnboardingAndConsent(
  userId: string
): Promise<UserPrivacyConsentState | null> {
  const local = loadLocalPrivacyConsent(userId);
  if (!auth.currentUser || auth.currentUser.uid !== userId) {
    return local;
  }

  const profilePath = `users/${userId}`;
  const consentPath = `users/${userId}/consents/privacy_v1`;

  try {
    const [profileSnap, consentSnap] = await Promise.all([
      getDocFromServer(doc(db, 'users', userId)).catch(() => null),
      getDocFromServer(doc(db, 'users', userId, 'consents', 'privacy_v1')).catch(() => null),
    ]);

    const profileData = profileSnap?.exists() ? profileSnap.data() : null;
    const consentData = consentSnap?.exists() ? consentSnap.data() : null;

    if (!profileData && !consentData) {
      return local;
    }

    const onboardingCompleted = Boolean(profileData?.onboardingCompleted) || Boolean(consentData);
    const allowCatalog = Boolean(consentData?.allowCatalogAndConnections);
    const allowEncrypted = Boolean(consentData?.allowEncryptedConnectionStorage);
    const revoked = Boolean(consentData?.revoked);

    const state: UserPrivacyConsentState = {
      onboardingCompleted,
      consentGranted:
        !revoked &&
        (Boolean(profileData?.consentGranted) || (allowCatalog && allowEncrypted)),
      policyVersion: String(consentData?.policyVersion || PRIVACY_POLICY_VERSION),
      consentVersion: String(consentData?.consentVersion || CONSENT_VERSION),
      allowCatalogAndConnections: allowCatalog,
      allowEncryptedConnectionStorage: allowEncrypted,
      browserNotificationsChoice: (consentData?.browserNotificationsChoice ||
        'default') as BrowserNotificationChoice,
      revoked,
      updatedAt:
        consentData?.updatedAt instanceof Timestamp
          ? consentData.updatedAt.toDate().toISOString()
          : new Date().toISOString(),
    };

    saveLocalPrivacyConsent(userId, state);
    return state;
  } catch (error) {
    try {
      handleFirestoreError(error, OperationType.GET, `${profilePath} | ${consentPath}`);
    } catch {
      return local;
    }
  }
}

export async function saveOnboardingAndConsent(
  userId: string,
  params: {
    allowCatalogAndConnections: boolean;
    allowEncryptedConnectionStorage: boolean;
    browserNotificationsChoice: BrowserNotificationChoice;
    revoked?: boolean;
  }
): Promise<UserPrivacyConsentState> {
  const revoked = Boolean(params.revoked);
  const consentGranted =
    !revoked && params.allowCatalogAndConnections && params.allowEncryptedConnectionStorage;

  const state: UserPrivacyConsentState = {
    onboardingCompleted: true,
    consentGranted,
    policyVersion: PRIVACY_POLICY_VERSION,
    consentVersion: CONSENT_VERSION,
    allowCatalogAndConnections: params.allowCatalogAndConnections,
    allowEncryptedConnectionStorage: params.allowEncryptedConnectionStorage,
    browserNotificationsChoice: params.browserNotificationsChoice,
    revoked,
    updatedAt: new Date().toISOString(),
  };

  saveLocalPrivacyConsent(userId, state);

  if (!auth.currentUser || auth.currentUser.uid !== userId) {
    return state;
  }

  const userPath = `users/${userId}`;
  const consentPath = `users/${userId}/consents/privacy_v1`;

  const providerIds = auth.currentUser.providerData?.map((p) => p.providerId) || [];
  const detectedProvider: AuthProviderKind = providerIds.includes('google.com')
    ? 'google'
    : providerIds.includes('phone') || (auth.currentUser.phoneNumber && !auth.currentUser.email)
    ? 'phone'
    : 'password';
  const cleanEmail = auth.currentUser.email ? auth.currentUser.email.trim().slice(0, 254) : '';
  const cleanDisplayName = auth.currentUser.displayName
    ? auth.currentUser.displayName.trim().slice(0, 120)
    : '';

  try {
    const userRef = doc(db, 'users', userId);
    const userSnap = await getDocFromServer(userRef).catch(() => null);

    if (userSnap && userSnap.exists()) {
      await updateDoc(userRef, {
        onboardingCompleted: true,
        consentGranted,
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(userRef, {
        uid: userId,
        ...(cleanEmail.length >= 3 ? { email: cleanEmail } : {}),
        ...(cleanDisplayName.length >= 1 ? { displayName: cleanDisplayName } : {}),
        role: 'USER',
        authProvider: detectedProvider,
        onboardingCompleted: true,
        consentGranted,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, userPath);
  }

  try {
    const consentRef = doc(db, 'users', userId, 'consents', 'privacy_v1');
    const consentSnap = await getDocFromServer(consentRef).catch(() => null);

    const payload = {
      policyVersion: PRIVACY_POLICY_VERSION,
      consentVersion: CONSENT_VERSION,
      allowCatalogAndConnections: params.allowCatalogAndConnections,
      allowEncryptedConnectionStorage: params.allowEncryptedConnectionStorage,
      browserNotificationsChoice: params.browserNotificationsChoice,
      revoked,
    };

    if (consentSnap && consentSnap.exists()) {
      await updateDoc(consentRef, {
        ...payload,
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(consentRef, {
        uid: userId,
        ...payload,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, consentPath);
  }

  return state;
}

export async function loadAppCatalogStatesFromFirestore(
  userId: string
): Promise<Record<string, FirestoreAppCatalogStateRecord>> {
  if (!auth.currentUser || auth.currentUser.uid !== userId) return {};
  const path = `users/${userId}/appCatalogStates`;
  try {
    const q = query(
      collection(db, 'users', userId, 'appCatalogStates'),
      where('uid', '==', userId),
      limit(60)
    );
    const snap = await getDocs(q);
    const out: Record<string, FirestoreAppCatalogStateRecord> = {};
    for (const d of snap.docs) {
      const data = d.data();
      out[d.id] = {
        appId: String(data.appId || d.id),
        status: (data.status || 'Unknown') as FirestoreAppCatalogStateRecord['status'],
        markedByUser: Boolean(data.markedByUser),
        deepLinkConfirmed: (data.deepLinkConfirmed || 'untested') as 'yes' | 'no' | 'untested',
        relatedAppDetected: Boolean(data.relatedAppDetected),
        updatedAt:
          data.updatedAt instanceof Timestamp
            ? data.updatedAt.toDate().toISOString()
            : new Date().toISOString(),
      };
    }
    return out;
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}

export async function saveAppCatalogStateInFirestore(
  userId: string,
  state: Omit<FirestoreAppCatalogStateRecord, 'updatedAt'>
): Promise<void> {
  if (!auth.currentUser || auth.currentUser.uid !== userId) return;
  const safeAppId = state.appId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 64);
  if (!safeAppId) return;
  const docPath = `users/${userId}/appCatalogStates/${safeAppId}`;
  try {
    const ref = doc(db, 'users', userId, 'appCatalogStates', safeAppId);
    const existingSnap = await getDocFromServer(ref).catch(() => null);
    if (existingSnap && existingSnap.exists()) {
      await updateDoc(ref, {
        status: state.status,
        markedByUser: Boolean(state.markedByUser),
        deepLinkConfirmed: state.deepLinkConfirmed,
        relatedAppDetected: Boolean(state.relatedAppDetected),
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(ref, {
        uid: userId,
        appId: safeAppId,
        status: state.status,
        markedByUser: Boolean(state.markedByUser),
        deepLinkConfirmed: state.deepLinkConfirmed,
        relatedAppDetected: Boolean(state.relatedAppDetected),
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, docPath);
  }
}

export async function deleteAllAppCatalogStatesInFirestore(userId: string): Promise<void> {
  if (!auth.currentUser || auth.currentUser.uid !== userId) return;
  const path = `users/${userId}/appCatalogStates`;
  try {
    const q = query(
      collection(db, 'users', userId, 'appCatalogStates'),
      where('uid', '==', userId),
      limit(100)
    );
    const snap = await getDocs(q);
    await Promise.all(snap.docs.map((d) => deleteDoc(d.ref)));
  } catch (error) {
    handleFirestoreError(error, OperationType.DELETE, path);
  }
}

export interface FirestoreDeliveryJobSnapshot {
  id: string;
  notificationId: string;
  priority: string;
  state: string;
  channel: string;
  attempt: number;
  nextAttemptAt: string;
  idempotencyKey: string;
  history: Array<{
    timestamp: string;
    from: string;
    event: string;
    to: string;
    channel: string;
    result: string;
  }>;
}

export async function syncDeliveryJobToFirestore(
  uid: string,
  job: FirestoreDeliveryJobSnapshot
): Promise<void> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return;
  const cleanJobId = job.id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 128);
  if (!cleanJobId) return;
  const path = `users/${uid}/deliveryJobs/${cleanJobId}`;
  try {
    await ensureUserProfileInFirestore(uid);
    const ref = doc(db, 'users', uid, 'deliveryJobs', cleanJobId);
    const snap = await getDocFromServer(ref).catch(() => null);
    const trimmedHistory = (job.history || []).slice(-20).map((h) => ({
      timestamp: String(h.timestamp || ''),
      from: String(h.from || ''),
      event: String(h.event || ''),
      to: String(h.to || ''),
      channel: String(h.channel || ''),
      result: String(h.result || '').slice(0, 180),
    }));

    const payload = {
      id: cleanJobId,
      uid,
      notificationId: job.notificationId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 128),
      priority: String(job.priority || 'NORMAL').slice(0, 16),
      state: String(job.state || 'QUEUED').slice(0, 32),
      channel: String(job.channel || 'none').slice(0, 16),
      attempt: Math.max(0, Math.floor(Number(job.attempt) || 0)),
      nextAttemptAt: String(job.nextAttemptAt || new Date().toISOString()).slice(0, 48),
      idempotencyKey: String(job.idempotencyKey || cleanJobId).slice(0, 160),
      history: trimmedHistory,
    };

    if (snap && snap.exists()) {
      await updateDoc(ref, {
        ...payload,
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(ref, {
        ...payload,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function loadDeliveryJobsFromFirestore(
  uid: string
): Promise<FirestoreDeliveryJobSnapshot[]> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return [];
  const path = `users/${uid}/deliveryJobs`;
  try {
    const q = query(
      collection(db, 'users', uid, 'deliveryJobs'),
      where('uid', '==', uid),
      orderBy('updatedAt', 'desc'),
      limit(50)
    );
    const snap = await getDocs(q);
    return snap.docs.map((d) => {
      const data = d.data();
      return {
        id: String(data.id || d.id),
        notificationId: String(data.notificationId || ''),
        priority: String(data.priority || 'NORMAL'),
        state: String(data.state || 'QUEUED'),
        channel: String(data.channel || 'none'),
        attempt: Number(data.attempt || 0),
        nextAttemptAt: String(data.nextAttemptAt || ''),
        idempotencyKey: String(data.idempotencyKey || ''),
        history: Array.isArray(data.history) ? data.history : [],
      };
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.LIST, path);
  }
}

export interface FirestoreUserPriorityModel {
  version: number;
  personalizationEnabled: boolean;
  feedbackCount: number;
  bias: number;
  weights: Record<string, number>;
  thresholds: {
    critical: number;
    high: number;
    normal: number;
    hysteresis: number;
  };
  urgentKeywords: string[];
  quietHours: {
    enabled: boolean;
    startHourUtc: number;
    endHourUtc: number;
    dndActive?: boolean;
  };
  sourceReliability: Record<string, number>;
  driftWarning: boolean;
  driftL2Distance: number;
  updatedAt?: string;
}

export async function loadPriorityModelFromFirestore(
  uid: string
): Promise<FirestoreUserPriorityModel | null> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return null;
  const path = `users/${uid}/priorityModel/default`;
  try {
    const snap = await getDocFromServer(doc(db, 'users', uid, 'priorityModel', 'default'));
    if (!snap.exists()) return null;
    const data = snap.data();
    return {
      version: Number(data.version || 1),
      personalizationEnabled:
        typeof data.personalizationEnabled === 'boolean' ? data.personalizationEnabled : true,
      feedbackCount: Number(data.feedbackCount || 0),
      bias: Number(data.bias ?? -2.2),
      weights:
        data.weights && typeof data.weights === 'object'
          ? (data.weights as Record<string, number>)
          : {},
      thresholds:
        data.thresholds && typeof data.thresholds === 'object'
          ? (data.thresholds as FirestoreUserPriorityModel['thresholds'])
          : { critical: 0.85, high: 0.65, normal: 0.35, hysteresis: 0.04 },
      urgentKeywords: Array.isArray(data.urgentKeywords)
        ? data.urgentKeywords.map((x: unknown) => String(x))
        : [],
      quietHours:
        data.quietHours && typeof data.quietHours === 'object'
          ? (data.quietHours as FirestoreUserPriorityModel['quietHours'])
          : { enabled: false, startHourUtc: 22, endHourUtc: 7, dndActive: false },
      sourceReliability:
        data.sourceReliability && typeof data.sourceReliability === 'object'
          ? (data.sourceReliability as Record<string, number>)
          : {},
      driftWarning: Boolean(data.driftWarning),
      driftL2Distance: Number(data.driftL2Distance || 0),
      updatedAt:
        data.updatedAt instanceof Timestamp
          ? data.updatedAt.toDate().toISOString()
          : new Date().toISOString(),
    };
  } catch (error) {
    try {
      handleFirestoreError(error, OperationType.GET, path);
    } catch {
      return null;
    }
  }
}

export async function savePriorityModelToFirestore(
  uid: string,
  model: FirestoreUserPriorityModel
): Promise<void> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return;
  const path = `users/${uid}/priorityModel/default`;
  try {
    await ensureUserProfileInFirestore(uid);
    const ref = doc(db, 'users', uid, 'priorityModel', 'default');
    const existingSnap = await getDocFromServer(ref).catch(() => null);

    const payload = {
      version: Math.max(1, Math.floor(Number(model.version) || 1)),
      personalizationEnabled: Boolean(model.personalizationEnabled),
      feedbackCount: Math.max(0, Math.floor(Number(model.feedbackCount) || 0)),
      bias: Math.max(-10, Math.min(10, Number(model.bias) || 0)),
      weights: model.weights || {},
      thresholds: model.thresholds || { critical: 0.85, high: 0.65, normal: 0.35, hysteresis: 0.04 },
      urgentKeywords: (model.urgentKeywords || [])
        .map((k) => String(k).trim().slice(0, 40))
        .filter(Boolean)
        .slice(0, 30),
      quietHours: model.quietHours || { enabled: false, startHourUtc: 22, endHourUtc: 7, dndActive: false },
      sourceReliability: model.sourceReliability || {},
      driftWarning: Boolean(model.driftWarning),
      driftL2Distance: Math.max(0, Math.min(100, Number(model.driftL2Distance) || 0)),
    };

    if (existingSnap && existingSnap.exists()) {
      await updateDoc(ref, {
        ...payload,
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(ref, {
        uid,
        ...payload,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export interface FirestoreDedupThreadPayload {
  threadId: string;
  lastMemberAt: string;
  memberCount: number;
  memberIds: string[];
  sourceId: string;
  senderId: string;
  category: string;
  topPriority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  lowestTrust: 'VERIFIED' | 'GATEWAY_ATTESTED' | 'UNVERIFIED';
  status: 'ACTIVE' | 'RESOLVED' | 'MUTED';
  stageMatched: 'EXACT' | 'MINHASH' | 'SEMANTIC_ONNX' | 'TFIDF_FALLBACK' | 'NONE';
  lastSimilarity: number;
  containsEphemeral?: boolean;
}

export async function syncDedupThreadToFirestore(
  uid: string,
  thread: FirestoreDedupThreadPayload
): Promise<void> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return;
  const cleanThreadId = thread.threadId.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128);
  if (!cleanThreadId) return;
  const path = `users/${uid}/threads/${cleanThreadId}`;
  try {
    const profileReady = await ensureUserProfileInFirestore(uid);
    if (!profileReady) return;
    const ref = doc(db, 'users', uid, 'threads', cleanThreadId);
    const snap = await getDocFromServer(ref).catch(() => null);
    const memberIds = (thread.memberIds || [cleanThreadId])
      .map((id) => String(id).replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128))
      .filter(Boolean)
      .slice(-50);

    const rawPrio = String(thread.topPriority || 'MEDIUM').toUpperCase();
    const normalizedPriority = (rawPrio === 'NORMAL'
      ? 'MEDIUM'
      : ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(rawPrio)
      ? rawPrio
      : 'MEDIUM') as FirestoreDedupThreadPayload['topPriority'];
    const rawTrust = String(thread.lowestTrust || 'UNVERIFIED').toUpperCase();
    const normalizedTrust = (['VERIFIED', 'GATEWAY_ATTESTED', 'UNVERIFIED'].includes(rawTrust)
      ? rawTrust
      : 'UNVERIFIED') as FirestoreDedupThreadPayload['lowestTrust'];
    const rawStatus = String(thread.status || 'ACTIVE').toUpperCase();
    const normalizedStatus = (['ACTIVE', 'RESOLVED', 'MUTED'].includes(rawStatus)
      ? rawStatus
      : 'ACTIVE') as FirestoreDedupThreadPayload['status'];
    const rawStage = String(thread.stageMatched || 'NONE').toUpperCase();
    const normalizedStage = ([
      'EXACT',
      'MINHASH',
      'SEMANTIC_ONNX',
      'TFIDF_FALLBACK',
      'NONE',
    ].includes(rawStage)
      ? rawStage
      : 'NONE') as FirestoreDedupThreadPayload['stageMatched'];

    const payload = {
      lastMemberAt: String(thread.lastMemberAt || new Date().toISOString()).trim().slice(0, 64) || new Date().toISOString(),
      memberCount: Math.max(1, Math.min(500, Math.floor(Number(thread.memberCount) || 1))),
      memberIds: memberIds.length > 0 ? memberIds : [cleanThreadId],
      topPriority: normalizedPriority,
      lowestTrust: normalizedTrust,
      status: normalizedStatus,
      stageMatched: normalizedStage,
      lastSimilarity: Math.max(0, Math.min(1, Number(thread.lastSimilarity) || 0)),
      containsEphemeral: Boolean(thread.containsEphemeral),
    };

    if (snap && snap.exists()) {
      await updateDoc(ref, {
        ...payload,
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(ref, {
        uid,
        threadId: cleanThreadId,
        sourceId: String(thread.sourceId || '').trim().slice(0, 64) || 'direct',
        senderId: String(thread.senderId || '').trim().slice(0, 128) || uid,
        category: String(thread.category || '').trim().slice(0, 32) || 'work',
        ...payload,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function deleteDedupThreadFromFirestore(
  uid: string,
  threadId: string
): Promise<void> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return;
  const cleanThreadId = threadId.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 128);
  if (!cleanThreadId) return;
  const path = `users/${uid}/threads/${cleanThreadId}`;
  try {
    await deleteDoc(doc(db, 'users', uid, 'threads', cleanThreadId));
  } catch (error) {
    try {
      handleFirestoreError(error, OperationType.DELETE, path);
    } catch {
      // Ignore if thread was ephemeral-only or already removed
    }
  }
}

export interface FirestoreDedupSettingsRecord {
  dedupEnabled: boolean;
  mergeThreshold: number;
  reviewThreshold: number;
  effectiveMergeThreshold: number;
  windowMinutes: number;
  neverMergeCategories: string[];
  feedbackCount: number;
}

export async function loadDedupSettingsFromFirestore(
  uid: string
): Promise<FirestoreDedupSettingsRecord | null> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return null;
  const path = `users/${uid}/dedupSettings/default`;
  try {
    const snap = await getDocFromServer(doc(db, 'users', uid, 'dedupSettings', 'default'));
    if (!snap.exists()) return null;
    const data = snap.data();
    return {
      dedupEnabled: typeof data.dedupEnabled === 'boolean' ? data.dedupEnabled : true,
      mergeThreshold: Number(data.mergeThreshold ?? 0.88),
      reviewThreshold: Number(data.reviewThreshold ?? 0.78),
      effectiveMergeThreshold: Number(data.effectiveMergeThreshold ?? 0.88),
      windowMinutes: Number(data.windowMinutes ?? 5),
      neverMergeCategories: Array.isArray(data.neverMergeCategories)
        ? data.neverMergeCategories.map((c: unknown) => String(c))
        : ['security', 'otp', 'auth', 'provenance'],
      feedbackCount: Number(data.feedbackCount ?? 0),
    };
  } catch (error) {
    try {
      handleFirestoreError(error, OperationType.GET, path);
    } catch {
      return null;
    }
  }
}

export async function saveDedupSettingsToFirestore(
  uid: string,
  settings: FirestoreDedupSettingsRecord
): Promise<void> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return;
  const path = `users/${uid}/dedupSettings/default`;
  try {
    await ensureUserProfileInFirestore(uid);
    const ref = doc(db, 'users', uid, 'dedupSettings', 'default');
    const snap = await getDocFromServer(ref).catch(() => null);
    const categories = Array.from(
      new Set([
        'security',
        'otp',
        'auth',
        'provenance',
        ...(settings.neverMergeCategories || []).map((c) => String(c).trim().toLowerCase()),
      ])
    )
      .filter(Boolean)
      .slice(0, 12);

    const payload = {
      dedupEnabled: Boolean(settings.dedupEnabled),
      mergeThreshold: Math.max(0.5, Math.min(0.99, Number(settings.mergeThreshold) || 0.88)),
      reviewThreshold: Math.max(0.5, Math.min(0.99, Number(settings.reviewThreshold) || 0.78)),
      effectiveMergeThreshold: Math.max(
        0.8,
        Math.min(0.98, Number(settings.effectiveMergeThreshold) || 0.88)
      ),
      windowMinutes: Math.max(5, Math.min(180, Math.round(Number(settings.windowMinutes) || 5))),
      neverMergeCategories: categories,
      feedbackCount: Math.max(0, Math.floor(Number(settings.feedbackCount) || 0)),
    };

    if (snap && snap.exists()) {
      await updateDoc(ref, {
        ...payload,
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(ref, {
        uid,
        ...payload,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, path);
  }
}

export async function applyFirebaseAuthPersistence(keepSignedIn: boolean): Promise<void> {
  try {
    await setPersistence(
      auth,
      keepSignedIn ? browserLocalPersistence : browserSessionPersistence
    );
  } catch {
    // Fallback cleanly if browser restricts persistence mode
  }
}

export interface SmartFirestoreAccountState {
  exists: boolean;
  onboardingCompleted: boolean;
  keySetupCompleted: boolean;
  emailVerified: boolean;
  inactivityTimeoutDays: number;
  sessionVersion: number;
  authMethods: string[];
  lastLoginAt?: string;
}

export async function loadSmartAccountStateFromFirestore(
  uid: string
): Promise<SmartFirestoreAccountState | null> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return null;
  const path = `users/${uid}`;
  try {
    const snap = await getDocFromServer(doc(db, 'users', uid));
    if (!snap.exists()) {
      return {
        exists: false,
        onboardingCompleted: false,
        keySetupCompleted: false,
        emailVerified: Boolean(auth.currentUser.emailVerified),
        inactivityTimeoutDays: 14,
        sessionVersion: 1,
        authMethods: [],
      };
    }
    const data = snap.data();
    return {
      exists: true,
      onboardingCompleted: Boolean(data.onboardingCompleted),
      keySetupCompleted: Boolean(data.keySetupCompleted),
      emailVerified: Boolean(data.emailVerified ?? auth.currentUser.emailVerified),
      inactivityTimeoutDays:
        typeof data.inactivityTimeoutDays === 'number' ? data.inactivityTimeoutDays : 14,
      sessionVersion: typeof data.sessionVersion === 'number' ? data.sessionVersion : 1,
      authMethods: Array.isArray(data.authMethods) ? data.authMethods.map(String) : [],
      ...(data.lastLoginAt ? { lastLoginAt: String(data.lastLoginAt) } : {}),
    };
  } catch (error) {
    try {
      handleFirestoreError(error, OperationType.GET, path);
    } catch {
      return null;
    }
  }
}

export async function saveSmartSecuritySettingsToFirestore(
  uid: string,
  updates: {
    authProvider?: AuthProviderKind;
    authMethods?: string[];
    keySetupCompleted?: boolean;
    onboardingCompleted?: boolean;
    inactivityTimeoutDays?: number;
    sessionVersion?: number;
    emailVerified?: boolean;
    email?: string;
    displayName?: string;
  }
): Promise<void> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return;
  const path = `users/${uid}`;
  try {
    const userRef = doc(db, 'users', uid);
    const snap = await getDocFromServer(userRef).catch(() => null);
    const cleanMethods = updates.authMethods
      ? [...new Set(updates.authMethods.map((m) => String(m).slice(0, 32)))].slice(0, 8)
      : undefined;

    const cleanEmail = (updates.email || auth.currentUser.email || '').trim().slice(0, 254);
    const cleanDisplayName = (updates.displayName || auth.currentUser.displayName || '')
      .trim()
      .slice(0, 120);

    if (snap && snap.exists()) {
      await updateDoc(userRef, {
        ...(updates.authProvider ? { authProvider: updates.authProvider } : {}),
        ...(cleanMethods ? { authMethods: cleanMethods } : {}),
        ...(typeof updates.keySetupCompleted === 'boolean'
          ? { keySetupCompleted: updates.keySetupCompleted }
          : {}),
        ...(typeof updates.onboardingCompleted === 'boolean'
          ? { onboardingCompleted: updates.onboardingCompleted }
          : {}),
        ...(typeof updates.inactivityTimeoutDays === 'number'
          ? {
              inactivityTimeoutDays: Math.max(
                1,
                Math.min(90, Math.round(updates.inactivityTimeoutDays))
              ),
            }
          : {}),
        ...(typeof updates.sessionVersion === 'number'
          ? { sessionVersion: Math.max(1, Math.floor(updates.sessionVersion)) }
          : {}),
        ...(typeof updates.emailVerified === 'boolean'
          ? { emailVerified: updates.emailVerified }
          : {}),
        ...(updates.email && updates.email.trim().length >= 3
          ? { email: updates.email.trim().slice(0, 254) }
          : {}),
        ...(updates.displayName && updates.displayName.trim().length >= 1
          ? { displayName: updates.displayName.trim().slice(0, 120) }
          : {}),
        lastLoginAt: new Date().toISOString(),
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(userRef, {
        uid,
        role: 'USER',
        authProvider: updates.authProvider || 'password',
        ...(cleanEmail.length >= 3 ? { email: cleanEmail } : {}),
        ...(cleanDisplayName.length >= 1 ? { displayName: cleanDisplayName } : {}),
        emailVerified: Boolean(auth.currentUser.emailVerified),
        keySetupCompleted: Boolean(updates.keySetupCompleted),
        onboardingCompleted: Boolean(updates.onboardingCompleted),
        inactivityTimeoutDays: Math.max(
          1,
          Math.min(90, Math.round(updates.inactivityTimeoutDays ?? 14))
        ),
        sessionVersion: Math.max(1, Math.floor(updates.sessionVersion ?? 1)),
        ...(cleanMethods ? { authMethods: cleanMethods } : {}),
        lastLoginAt: new Date().toISOString(),
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    try {
      handleFirestoreError(error, OperationType.WRITE, path);
    } catch {
      // Non-fatal fallback to backend/local store
    }
  }
}

export interface FirestoreKeyBackupPayload {
  v: 1;
  userId: string;
  kdf: 'PBKDF2-HMAC-SHA256';
  iterations: number;
  cipher: 'AES-256-GCM';
  salt: string;
  iv: string;
  encryptedPrivateKeysBundle: string;
  ed25519PublicKey: string;
  ed25519Kid: string;
  fingerprintHex: string;
  fingerprintWords: string[];
  ecdhPublicJwk: JsonWebKey;
  ecdsaPublicJwk: JsonWebKey;
  createdAt: string;
  updatedAt: string;
}

export async function saveEncryptedKeyBackupToFirestore(
  uid: string,
  backup: FirestoreKeyBackupPayload
): Promise<void> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return;
  const path = `users/${uid}/keyBackups/default`;
  try {
    const ref = doc(db, 'users', uid, 'keyBackups', 'default');
    const snap = await getDocFromServer(ref).catch(() => null);
    const payload = {
      v: 1,
      kdf: 'PBKDF2-HMAC-SHA256',
      iterations: Math.max(100_000, Math.min(1_000_000, Math.floor(backup.iterations || 150_000))),
      cipher: 'AES-256-GCM',
      salt: String(backup.salt).slice(0, 128),
      iv: String(backup.iv).slice(0, 128),
      encryptedPrivateKeysBundle: String(backup.encryptedPrivateKeysBundle).slice(0, 16384),
      ed25519PublicKey: String(backup.ed25519PublicKey).slice(0, 128),
      ed25519Kid: String(backup.ed25519Kid).slice(0, 128),
      fingerprintHex: String(backup.fingerprintHex || '').slice(0, 128),
      fingerprintWords: (backup.fingerprintWords || []).slice(0, 12).map((w) => String(w).slice(0, 32)),
      ecdhPublicJwkJson: JSON.stringify(backup.ecdhPublicJwk).slice(0, 2048),
      ecdsaPublicJwkJson: JSON.stringify(backup.ecdsaPublicJwk).slice(0, 2048),
    };

    if (snap && snap.exists()) {
      await updateDoc(ref, {
        ...payload,
        updatedAt: serverTimestamp(),
      });
    } else {
      await setDoc(ref, {
        uid,
        ...payload,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });
    }
  } catch (error) {
    try {
      handleFirestoreError(error, OperationType.WRITE, path);
    } catch {
      // Non-fatal: server API vault still holds backup
    }
  }
}

export async function loadEncryptedKeyBackupFromFirestore(
  uid: string
): Promise<FirestoreKeyBackupPayload | null> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return null;
  const path = `users/${uid}/keyBackups/default`;
  try {
    const snap = await getDocFromServer(doc(db, 'users', uid, 'keyBackups', 'default'));
    if (!snap.exists()) return null;
    const data = snap.data();
    return {
      v: 1,
      userId: uid,
      kdf: 'PBKDF2-HMAC-SHA256',
      iterations: Number(data.iterations || 150_000),
      cipher: 'AES-256-GCM',
      salt: String(data.salt || ''),
      iv: String(data.iv || ''),
      encryptedPrivateKeysBundle: String(data.encryptedPrivateKeysBundle || ''),
      ed25519PublicKey: String(data.ed25519PublicKey || ''),
      ed25519Kid: String(data.ed25519Kid || ''),
      fingerprintHex: String(data.fingerprintHex || ''),
      fingerprintWords: Array.isArray(data.fingerprintWords) ? data.fingerprintWords.map(String) : [],
      ecdhPublicJwk: JSON.parse(String(data.ecdhPublicJwkJson || '{}')),
      ecdsaPublicJwk: JSON.parse(String(data.ecdsaPublicJwkJson || '{}')),
      createdAt:
        data.createdAt instanceof Timestamp
          ? data.createdAt.toDate().toISOString()
          : new Date().toISOString(),
      updatedAt:
        data.updatedAt instanceof Timestamp
          ? data.updatedAt.toDate().toISOString()
          : new Date().toISOString(),
    };
  } catch (error) {
    try {
      handleFirestoreError(error, OperationType.GET, path);
    } catch {
      return null;
    }
  }
}

export async function recordLoginAuditToFirestore(
  uid: string,
  entry: {
    id: string;
    timestamp: string;
    deviceType: string;
    browserSummary: string;
    ipPrefixHash: string;
    deviceIdHash: string;
    method: string;
    isNewDevice: boolean;
  }
): Promise<void> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return;
  const cleanId = entry.id.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 120) || `aud_${Date.now()}`;
  const path = `users/${uid}/loginAudits/${cleanId}`;
  try {
    await setDoc(doc(db, 'users', uid, 'loginAudits', cleanId), {
      uid,
      timestamp: String(entry.timestamp).slice(0, 64),
      deviceType: String(entry.deviceType).slice(0, 32),
      browserSummary: String(entry.browserSummary).slice(0, 64),
      ipPrefixHash: String(entry.ipPrefixHash).slice(0, 64),
      deviceIdHash: String(entry.deviceIdHash).slice(0, 64),
      method: String(entry.method).slice(0, 40),
      isNewDevice: Boolean(entry.isNewDevice),
      createdAt: serverTimestamp(),
    });
  } catch (error) {
    try {
      handleFirestoreError(error, OperationType.CREATE, path);
    } catch {
      // Non-fatal
    }
  }
}

export async function deleteUserProfileInFirestore(uid: string): Promise<void> {
  if (!auth.currentUser || auth.currentUser.uid !== uid) return;
  const path = `users/${uid}`;
  try {
    await deleteDoc(doc(db, 'users', uid));
  } catch (error) {
    try {
      handleFirestoreError(error, OperationType.DELETE, path);
    } catch {
      // Best-effort cleanup
    }
  }
}



