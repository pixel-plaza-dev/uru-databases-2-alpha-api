import { JwtTokenData } from '@prisma/client';

export type JwtTokenDataCreate = Pick<JwtTokenData, 'expiresAt'>;
