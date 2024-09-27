import { IntersectionType, PartialType, PickType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class UserUpdateDto extends IntersectionType(
  PickType(UserDto, ['email'] as const),
  PartialType(PickType(UserDto, ['address', 'phone', 'name'] as const)),
) {}
