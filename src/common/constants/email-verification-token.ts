// Email Verification Token
export const EMAIL_VERIFICATION_TOKEN = {
  // Success messages
  SENT: 'Verification token sent to email',
  VERIFIED: 'Email verified',

  // Error messages
  ALREADY_VERIFIED: 'Email already verified',
  GET_NEW_TOKEN: 'Please go to /user/verify-email to get a new token',
  FAILED_TO_CREATE: 'Failed to create email verification token',
} as const;
