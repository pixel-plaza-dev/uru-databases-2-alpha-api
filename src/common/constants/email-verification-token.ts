// Email Verification Token
export const EMAIL_VERIFICATION_TOKEN = {
  // Success messages
  SENT: 'Verification token sent to email',
  VERIFIED: 'Email verified',

  // Error messages
  GET_NEW_TOKEN: 'Please go to /user/verify-email to get a new token',
} as const;
