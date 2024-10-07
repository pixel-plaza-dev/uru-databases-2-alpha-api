import { PasswordResetToken, UserEmail } from '@prisma/client';

export type PasswordResetTokenCreate = Pick<PasswordResetToken, 'expiresAt'> &
  Pick<UserEmail, 'email'>;
