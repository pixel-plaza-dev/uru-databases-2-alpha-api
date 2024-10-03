import { PasswordResetToken } from '@prisma/client';

export type PasswordResetTokenCreate = Pick<
  PasswordResetToken,
  'email' | 'expiresAt'
>;
