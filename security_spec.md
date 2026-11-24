# Firestore Security Specification (Phase 0)

## Data Invariants
1. **Strict Ownership**: Every document under `/users/{userId}` and its subcollections (`preferences`, `consents`, `appCatalogStates`, `chatThreads`, `messages`) belongs strictly to `request.auth.uid == userId`.
2. **Verified Identity**: Write operations require either a verified email (`request.auth.token.email_verified == true`, e.g., Google Sign-In) or Firebase Phone Authentication (`request.auth.token.firebase.sign_in_provider == 'phone'`).
3. **Immutable Ownership & Timestamps**: `uid` and `createdAt` can never be mutated after creation; `createdAt == request.time` on create and `updatedAt == request.time` on create/update.
4. **Role Escalation Prevention**: `UserAuthProfile.role` is strictly constrained to `'USER'` on client writes; clients cannot assign `'ADMIN'` or inject undeclared fields.
5. **Relational Master Gate**: Subcollection writes (`preferences`, `consents`, `appCatalogStates`, `chatThreads`, `messages`) verify ownership via `get(/databases/$(database)/documents/users/$(userId)).data.uid == request.auth.uid`, and `messages` additionally verify the parent `chatThreads/{threadId}` exists and belongs to `request.auth.uid`.
6. **Bounded Resource Sizes**: Every string field enforces explicit `.size()` bounds and IDs match `^[a-zA-Z0-9_\-]+$`.
7. **Consent & Catalog Privacy**: Only the owning verified user can read, update, or delete their `consents` and `appCatalogStates` records; server-only encrypted connection secrets are never written into client Firestore rules.
8. **Delivery Job Integrity & Terminal State Lock**: `/users/{userId}/deliveryJobs/{jobId}` belongs strictly to `request.auth.uid == userId`, stores zero plaintext notification content, enforces valid enum `state`/`priority`/`channel`, bounds `history.size() <= 50`, and locks terminal states (`DELIVERED_ACKED`, `FAILED_ALL_CHANNELS`, `CANCELLED`, `EXPIRED`) against subsequent updates.
9. **Ephemeral Data Isolation & Expiry Gate**: `/ephemeralMessages/{messageId}` allows client reads ONLY when `request.time < resource.data.expiresAt`, `resource.data.status in ['ACTIVE', 'READ']`, and caller is `senderId` or `recipientId`. Client updates and deletes to `ephemeralMessages` are unconditionally denied (`allow update, delete: if false;`) so no client can extend `expiresAt` or reset `status`. All client access to `/ephemeralKeys/{keyId}` and `/ephemeralTombstones/{tombstoneId}` is unconditionally denied (`allow read, write: if false;`).
10. **Zero-Trust Provenance & Key Transparency Log**: `/provenanceKeys/{kid}` stores ONLY public keys (never private seeds); authenticated users may read keys to verify senders and may create ONLY their own `ACTIVE` key entry (`incoming().userId == request.auth.uid`), while updates/deletes are denied from clients. `/keyLog/{entryId}` allows authenticated reads so clients can audit hash-chain continuity, while ALL client creates, updates, and deletes are denied (`allow write: if false;`). `/provenanceQuarantine/{qId}` is strictly server-only (`allow read, write: if false;`).
11. **Dynamic Sigmoid Priority Model Isolation**: `/users/{userId}/priorityModel/{modelId}` (`modelId == 'default'`) stores ONLY numeric model weights, bias, thresholds, urgent keyword config, quiet hours, and source reliability scores. Strict field allowlisting rejects any message plaintext or unmodeled fields.
12. **Semantic Deduplication Zero-Text & Zero-Vector Isolation**: `/users/{userId}/threads/{threadId}` and `/users/{userId}/dedupSettings/{settingId}` (`settingId == 'default'`) store ONLY non-sensitive metadata (`threadId`, `memberCount`, `memberIds`, `sourceId`, `senderId`, `category`, `topPriority`, `lowestTrust`, `status`, thresholds, toggles). Strict `hasOnly` allowlists make it mathematically impossible to persist notification plaintext or 384-dim embedding vectors into Firestore.

## Adversarial Test Matrix ("Dirty Dozen")
1. Unauthenticated read/write to `/users/{userId}` -> `PERMISSION_DENIED`.
2. Cross-user read/write to `/users/otherUid` -> `PERMISSION_DENIED`.
3. Self-escalation payload setting `role: "ADMIN"` -> `PERMISSION_DENIED`.
4. Unverified email account (`email_verified: false`) attempting write -> `PERMISSION_DENIED`.
5. Shadow field injection (`isVerified: true`) on profile, consent, catalog state, or deliveryJob -> `PERMISSION_DENIED`.
6. Spoofed `uid` mismatch (`data.uid != request.auth.uid`) -> `PERMISSION_DENIED`.
7. Client-forged timestamp (`createdAt != request.time`) -> `PERMISSION_DENIED`.
8. Oversized `systemInstruction` (> 2000 chars) or `text` (> 20000 chars) -> `PERMISSION_DENIED`.
9. Malicious document ID (`../admin` or > 128 chars) -> `PERMISSION_DENIED`.
10. Orphaned chat message or deliveryJob under nonexistent user profile -> `PERMISSION_DENIED`.
11. Mutating `createdAt`, `uid`, `idempotencyKey`, or updating a terminal `DeliveryJob` -> `PERMISSION_DENIED`.
12. Blanket `list` query on `/users` or cross-user `consents`, `appCatalogStates`, or `deliveryJobs` -> `PERMISSION_DENIED`.
13. Reading `/ephemeralMessages/{id}` after `request.time >= expiresAt`, mutating `status`/`expiresAt`, creating TTL > 900s, or reading/writing `/ephemeralKeys` -> `PERMISSION_DENIED`.
14. Writing/mutating `/keyLog/{entryId}`, revoking/rotating another user's `/provenanceKeys/{kid}`, or reading `/provenanceQuarantine` -> `PERMISSION_DENIED`.
15. Writing message plaintext fields (`text`/`message`/`body`) or invalid bias outside `[-10, 10]` to `/users/{userId}/priorityModel/default` -> `PERMISSION_DENIED`.
16. Injecting `text`, `rawText`, `embedding`, or `vector` into `/users/{userId}/threads/{threadId}` -> `PERMISSION_DENIED`.
17. Writing thresholds outside `[0.5, 0.99]` or cross-user reads/writes on `/users/{userId}/dedupSettings/default` -> `PERMISSION_DENIED`.
