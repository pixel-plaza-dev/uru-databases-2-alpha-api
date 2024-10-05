// Bcrypt errors
import { AUTH_GET_NEW_TOKEN } from './messages';

// Bcrypt errors
export const BCYPT_ERROR =
  'An error occurred while hashing the password' as const;

// User errors
export const USER_REGISTERED = 'Username already registered' as const;
export const USER_PASSWORDS_DO_NOT_MATCH = 'Passwords do not match' as const;
export const USER_WRONG_CREDENTIALS = 'Wrong email or password' as const;
export const USER_INVALID_PASSWORD = 'Invalid password' as const;

// Token errors
export const TOKEN_NOT_FOUND =
  `Authorization header not found. ${AUTH_GET_NEW_TOKEN}` as const;
export const INVALID_TOKEN = `Invalid token. ${AUTH_GET_NEW_TOKEN}` as const;
export const TOKEN_EXPIRED = `Token expired. ${AUTH_GET_NEW_TOKEN}` as const;
export const TOKEN_INVALIDATED = 'Token invalidated' as const;
export const TOKEN_NOT_FOUND_DB = 'Token not found in database' as const;

// Internal server error
export const INTERNAL_SERVER_ERROR = 'An error occurred!' as const;
export const UNREGISTERED_USR_ROLE_ACTION =
  'Unregistered user role action' as const;

// @nestjs/jwt errors
export const JWT_TOKEN_EXPIRED_ERROR = 'TokenExpiredError' as const;
