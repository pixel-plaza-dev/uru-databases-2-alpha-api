import { PickType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class UserDeleteDto extends PickType(UserDto, [
  'email',
  'password',
  'confirmPassword',
] as const) {}
