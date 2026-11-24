import {
  getSmsProviderMode,
  isSmsConfigured,
  isTwilioConfigured,
  getAllowedCountries,
  getMockAllowlist,
  maskPhone,
} from '../../../../../../lib/integrations/smsService.js';

export async function GET() {
  try {
    const mode = getSmsProviderMode();
    const smsConfigured = isSmsConfigured();
    const twilioConfigured = isTwilioConfigured();
    const allowedCountries = getAllowedCountries();
    const mockAllowlist = mode === 'mock' ? getMockAllowlist() : [];

    return Response.json({
      success: true,
      message:
        mode === 'mock'
          ? 'SMS verification is running in Demo Mode.'
          : twilioConfigured
          ? 'Twilio Verify SMS gateway is configured.'
          : 'Twilio Verify credentials are not configured yet.',
      data: {
        smsConfigured,
        mode,
        demoMode: mode === 'mock',
        twilioConfigured,
        allowedCountries,
        mockNumbersCount: mockAllowlist.length,
        mockTestNumbersMasked: mockAllowlist.map((num) => maskPhone(num)),
      },
    });
  } catch (err: any) {
    return Response.json(
      {
        success: false,
        message: err?.message || 'Unable to inspect SMS configuration status.',
        data: null,
      },
      { status: 500 }
    );
  }
}
