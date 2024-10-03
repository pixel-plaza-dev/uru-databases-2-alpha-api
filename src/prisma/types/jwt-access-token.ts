import { JwtAccessToken } from '@prisma/client';

export type JwtAccessTokenCreate = Pick<JwtAccessToken, 'expiresAt' | 'token'>;
