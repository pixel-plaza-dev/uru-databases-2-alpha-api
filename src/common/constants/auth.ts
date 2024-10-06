export const AUTH = {
  // Success messages
  SUCCESS: 'Authentication successful',
  ROLE_SUCCESS: 'User has required roles',

  // Error messages
  FAILED: 'Authentication failed',
  ROLE_FAILED: 'User does not have required roles',
  GET_NEW_TOKEN: 'Please go to /auth/refresh to get a new token or login again',
} as const;
