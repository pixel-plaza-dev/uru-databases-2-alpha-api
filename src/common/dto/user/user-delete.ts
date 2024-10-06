import { PickType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class UserDeleteDto extends PickType(UserDto, [
  'username',
  'password',
  'confirmPassword',
] as const) {}
