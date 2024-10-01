import convertToMilliseconds from '../utils/convert-to-ms';

// Server
export const IS_PRODUCTION = process.env.NODE_ENV === 'production';
export const SERVER_PORT = process.env.SERVER_PORT || 8000;

// Hashing
export const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS);

// JWT Secret
export const JWT_SECRET = process.env.JWT_SECRET;

// Tokens Options
export interface AuthTokenOptions {
  readonly secure: boolean;
  readonly httpOnly: boolean;
  readonly sameSite: 'strict' | 'lax' | 'none';
}

export const TOKEN_OPTIONS_DEFAULT: AuthTokenOptions = {
  secure: IS_PRODUCTION,
  httpOnly: true,
  sameSite: 'strict',
} as const;

// Tokens
export interface AuthTokenConfig {
  readonly name: string;
  readonly expiresIn: number;
  readonly options: AuthTokenOptions;
}

export const REFRESH_TOKEN: AuthTokenConfig = {
  name: process.env.REFRESH_TOKEN,
  expiresIn: convertToMilliseconds({
    days: parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN_DAYS),
  }),
  options: TOKEN_OPTIONS_DEFAULT,
} as const;

export const ACCESS_TOKEN: AuthTokenConfig = {
  name: process.env.ACCESS_TOKEN,
  expiresIn: convertToMilliseconds({
    minutes: parseInt(process.env.ACCESS_TOKEN_EXPIRES_IN_MINUTES),
  }),
  options: TOKEN_OPTIONS_DEFAULT,
} as const;

// Request added properties
export const REQUEST_USER = 'user';

// Decorators
export const IS_PUBLIC_KEY = 'isPublic';
