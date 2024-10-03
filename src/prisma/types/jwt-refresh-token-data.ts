import { JwtRefreshToken } from '@prisma/client';

export type JwtRefreshTokenCreate = Pick<
  JwtRefreshToken,
  'expiresAt' | 'token'
>;
