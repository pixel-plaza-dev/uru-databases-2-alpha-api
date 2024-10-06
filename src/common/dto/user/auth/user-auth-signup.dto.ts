import { PickType } from '@nestjs/swagger';
import { UserDto } from '../user.dto';

export class UserAuthSignupDto extends PickType(UserDto, [
  'email',
  'username',
  'password',
  'confirmPassword',
  'firstName',
  'lastName',
] as const) {}
