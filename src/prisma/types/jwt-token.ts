import { JwtToken } from '@prisma/client';

export type JwtTokenCreate = Pick<JwtToken, 'refreshToken' | 'accessToken'>;