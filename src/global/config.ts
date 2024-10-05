import convertToMilliseconds from '../utils/convert-to-ms';

// Server
export const IS_PRODUCTION = process.env.NODE_ENV === 'production';
export const SERVER_PORT = process.env.SERVER_PORT || 8000;

// Hashing
export const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS);

// JWT Secret
export const JWT_SECRET = process.env.JWT_SECRET;

// Expiration
export interface Expiration {
  readonly expiresIn: number;
}

// Tokens Options
export interface JwtTokenOptions {
  readonly secure: boolean;
  readonly httpOnly: boolean;
  readonly sameSite: 'strict' | 'lax' | 'none';
}

export const TOKEN_OPTIONS_DEFAULT: JwtTokenOptions = {
  secure: IS_PRODUCTION,
  httpOnly: true,
  sameSite: 'strict',
} as const;

// Tokens
export interface JwtTokenConfig extends Expiration {
  readonly name: string;
  readonly options: JwtTokenOptions;
}

export const REFRESH_TOKEN: JwtTokenConfig = {
  name: process.env.REFRESH_TOKEN,
  expiresIn: convertToMilliseconds({
    days: parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN_DAYS),
  }),
  options: TOKEN_OPTIONS_DEFAULT,
} as const;

export const ACCESS_TOKEN: JwtTokenConfig = {
  name: process.env.ACCESS_TOKEN,
  expiresIn: convertToMilliseconds({
    minutes: parseInt(process.env.ACCESS_TOKEN_EXPIRES_IN_MINUTES),
  }),
  options: TOKEN_OPTIONS_DEFAULT,
} as const;

// Email verification
export const EMAIL_VERIFICATION: Expiration = {
  expiresIn: convertToMilliseconds({
    hours: parseInt(process.env.EMAIL_VERIFICATION_EXPIRES_IN_HOURS),
  }),
} as const;

// Password reset
export const PASSWORD_RESET: Expiration = {
  expiresIn: convertToMilliseconds({
    hours: parseInt(process.env.PASSWORD_RESET_EXPIRES_IN_MINUTES),
  }),
} as const;

// Request added properties
export const REQUEST_USER = 'user';

// Request headers
export const USER_AGENT = 'user-agent';

// Decorators
export const IS_PUBLIC_KEY = 'isPublic';
export const ROLES_KEY = 'userRoles';
