// Email verification
import { Expiration } from './token';
import convertToMilliseconds from '../common/utils/convert-to-ms';

export const EMAIL_VERIFICATION: Expiration = {
  expiresIn: convertToMilliseconds({
    hours: parseInt(process.env.EMAIL_VERIFICATION_EXPIRES_IN_HOURS),
  }),
} as const;
