// Ping pong messages
export const PONG = 'pong' as const;

// User messages
export const USER_SIGNUP = 'User signed up' as const;
export const USER_LOGIN = 'User logged in' as const;
export const USER_LOGOUT = 'User logged out' as const;
export const USER_SESSIONS_CLOSED = 'All user sessions closed' as const;
export const USER_CHANGED_PASSWORD = 'User changed password' as const;
export const USER_FORGOT_PASSWORD = 'User forgot password' as const;
export const USER_CHANGED_EMAIL = 'User changed email' as const;
export const USER_UPDATED = 'User updated' as const;
export const USER_NOTHING_TO_UPDATE = 'Nothing to update' as const;
export const USER_DELETED = 'User deleted' as const;
export const USER_ADDED_ROLES = 'User added roles' as const;

// User role messages
export const getAddedRoleUserMessage = (
  username: string,
  targetUsername: string,
) => `User ${username} added role to ${targetUsername}` as const;

// Authentication messages
export const AUTH_FAILED = 'Authentication failed' as const;
export const AUTH_SUCCESS = 'Authentication successful' as const;

// Role messages
export const ROLE_AUTH_FAILED = 'User does not have required roles' as const;
export const ROLE_AUTH_SUCCESS = 'User has required roles' as const;

// Token messages
export const TOKEN_REFRESH_SUCCESS = 'Token refreshed' as const;
