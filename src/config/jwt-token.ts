// JWT Tokens
import convertToMilliseconds from '../common/utils/convert-to-ms';
import { Expiration, JwtTokenOptions, TOKEN_OPTIONS_DEFAULT } from './token';

export interface JwtTokenConfig extends Expiration {
  readonly name: string;
  readonly options: JwtTokenOptions;
}

// JWT Refresh Token Configuration
export const REFRESH_TOKEN: JwtTokenConfig = {
  name: process.env.REFRESH_TOKEN,
  expiresIn: convertToMilliseconds({
    days: parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN_DAYS),
  }),
  options: TOKEN_OPTIONS_DEFAULT,
} as const;

// JWT Access Token Configuration
export const ACCESS_TOKEN: JwtTokenConfig = {
  name: process.env.ACCESS_TOKEN,
  expiresIn: convertToMilliseconds({
    minutes: parseInt(process.env.ACCESS_TOKEN_EXPIRES_IN_MINUTES),
  }),
  options: TOKEN_OPTIONS_DEFAULT,
} as const;
