import { IntersectionType, PartialType, PickType } from '@nestjs/swagger';
import { UserDto } from '../user.dto';

export class UserAuthSignupDto extends IntersectionType(
  PartialType(PickType(UserDto, ['address', 'phone', 'birthDate'] as const)),
  PickType(UserDto, [
    'email',
    'username',
    'password',
    'confirmPassword',
    'firstName',
    'lastName',
  ] as const),
) {}
