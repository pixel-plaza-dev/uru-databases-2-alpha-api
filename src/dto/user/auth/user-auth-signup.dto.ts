import { IntersectionType, PartialType, PickType } from '@nestjs/swagger';
import { UserDto } from '../user.dto';

export class UserAuthSignupDto extends IntersectionType(
  PartialType(PickType(UserDto, ['address', 'phone'] as const)),
  PickType(UserDto, ['email', 'password', 'confirmPassword', 'name'] as const),
) {}
