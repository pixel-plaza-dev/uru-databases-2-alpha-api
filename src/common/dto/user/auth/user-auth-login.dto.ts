import { PickType } from '@nestjs/swagger';
import { UserDto } from '../user.dto';

export class UserAuthLoginDto extends PickType(UserDto, [
  'username',
  'password',
] as const) {}
