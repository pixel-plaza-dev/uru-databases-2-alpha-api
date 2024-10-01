import { PickType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class UserChangeRoleDto extends PickType(UserDto, ['role'] as const) {}
