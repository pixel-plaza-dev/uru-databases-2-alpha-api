// Password reset
import { Expiration } from './token';
import convertToMilliseconds from '../common/utils/convert-to-ms';

export const PASSWORD_RESET: Expiration = {
  expiresIn: convertToMilliseconds({
    hours: parseInt(process.env.PASSWORD_RESET_EXPIRES_IN_MINUTES),
  }),
} as const;
