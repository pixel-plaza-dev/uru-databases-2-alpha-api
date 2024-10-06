import { PickType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class UserResetPasswordDto extends PickType(UserDto, [
  'password',
  'confirmPassword',
] as const) {}
