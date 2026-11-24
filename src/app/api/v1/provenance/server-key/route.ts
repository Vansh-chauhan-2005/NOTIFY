import { getServerProvenanceKey } from '../../../../../lib/provenance/serverCrypto.js';
import { ensureServerKeyRegistered } from '../../../../../lib/provenance/store.js';
import { provenanceJson } from '../../../../../lib/provenance/http.js';

export async function GET() {
  try {
    await ensureServerKeyRegistered();
    const info = await getServerProvenanceKey();
    return provenanceJson({
      success: true,
      message: 'Server provenance public key loaded.',
      data: {
        kid: info.kid,
        alg: 'Ed25519',
        publicKey: info.publicKey,
        spkiPem: info.spkiPem,
        fingerprintHex: info.fingerprintHex,
        fingerprintWords: info.fingerprintWords,
        validFrom: info.validFrom,
        validUntil: info.validUntil,
        keySource: info.source,
      },
    });
  } catch (err: any) {
    return provenanceJson(
      { success: false, message: err?.message || 'Unable to load server provenance key.' },
      500
    );
  }
}
