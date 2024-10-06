import { PickType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class UserForgotPasswordDto extends PickType(UserDto, [
  'username',
  'email',
] as const) {}
