import { UserLoginAttempt } from '@prisma/client';

export type UserLoginAttemptCreate = Pick<
  UserLoginAttempt,
  'ip' | 'successful' | 'userAgent'
>;
