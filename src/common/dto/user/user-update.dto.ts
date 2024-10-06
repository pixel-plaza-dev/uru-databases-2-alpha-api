import { PartialType, PickType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class UserUpdateDto extends PartialType(
  PickType(UserDto, [
    'address',
    'phone',
    'birthDate',
    'firstName',
    'lastName',
  ] as const),
) {}
