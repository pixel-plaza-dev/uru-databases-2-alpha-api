import { PickType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class UserCloseAllSessionsDto extends PickType(UserDto, [
  'password',
] as const) {}
