import { PickType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class UserSendEmailVerificationTokenDto extends PickType(UserDto, [
  'email',
] as const) {}
