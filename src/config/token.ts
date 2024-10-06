// Expiration
import { IS_PRODUCTION } from './server';

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
