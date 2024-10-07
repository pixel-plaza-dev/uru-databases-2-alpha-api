import { EmailVerificationToken } from '@prisma/client';

export type EmailVerificationTokenSignup = Pick<
  EmailVerificationToken,
  'expiresAt'
>;

export type EmailVerificationTokenCreate = Pick<
  EmailVerificationToken,
  'expiresAt'
>;
