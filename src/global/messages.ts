// Ping pong messages
export const PONG = 'pong' as const;

// User messages
export const USER_SIGNUP =
  'User signed up. Check your email inbox to verify it' as const;
export const USER_LOGIN = 'User logged in' as const;
export const USER_LOGOUT = 'User logged out' as const;
export const USER_SESSIONS_CLOSED = 'All user sessions closed' as const;
export const USER_USERNAME_CHANGED = 'Username changed' as const;
export const USER_EMAIL_CHANGED = 'Email changed' as const;
export const USER_PASSWORD_CHANGED =
  'Password changed. Please login again' as const;
export const USER_NO_PASSWORD_CHANGE = 'No password change' as const;
export const USER_FORGOT_PASSWORD =
  'Password reset token sent to email' as const;
export const USER_UPDATED = 'User updated' as const;
export const USER_NOTHING_TO_UPDATE = 'Nothing to update' as const;
export const USER_DELETED = 'User deleted' as const;

// User role messages
export const USER_ADDED_ROLES = 'User added roles' as const;
export const USER_REMOVED_ROLES = 'User removed roles' as const;

// Authentication messages
export const AUTH_FAILED = 'Authentication failed' as const;
export const AUTH_SUCCESS = 'Authentication successful' as const;
export const AUTH_GET_NEW_TOKEN =
  'Please go to /auth/refresh to get a new token or login again' as const;

// Role messages
export const ROLE_AUTH_FAILED = 'User does not have required roles' as const;
export const ROLE_AUTH_SUCCESS = 'User has required roles' as const;

// Token messages
export const TOKEN_REFRESH_SUCCESS = 'Token refreshed' as const;
