import { EmailVerificationToken } from '@prisma/client';

export type EmailVerificationTokenCreate = Pick<
  EmailVerificationToken,
  'email' | 'expiresAt'
>;
