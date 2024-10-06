// User
export const USER = {
  // Success messages
  SIGNUP: 'User signed up. Check your email inbox to verify it',
  LOGIN: 'User logged in',
  LOGOUT: 'User logged out',
  SESSIONS_CLOSED: 'All user sessions closed',
  USERNAME_CHANGED: 'Username changed',
  EMAIL_CHANGED: 'Email changed',
  PASSWORD_CHANGED: 'Password changed. Please login again',
  FORGOT_PASSWORD: 'Password reset token sent to email',
  UPDATED: 'User updated',
  NOTHING_TO_UPDATE: 'Nothing to update',
  DELETED: 'User deleted',

  // Error messages
  REGISTERED: 'Username already registered',
  WRONG_CREDENTIALS: 'Wrong email or password',
  INVALID_PASSWORD: 'Invalid password',
  NO_PASSWORD_CHANGE: 'No password change',
  PASSWORDS_DO_NOT_MATCH: 'Passwords do not match',
} as const;
