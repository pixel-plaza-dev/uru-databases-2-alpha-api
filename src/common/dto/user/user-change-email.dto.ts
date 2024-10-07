import { IsEmail, IsNotEmpty } from 'class-validator';
import { ApiProperty, PickType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class UserChangeEmailDto extends PickType(UserDto, [
  'email',
] as const) {
  @IsEmail()
  @IsNotEmpty()
  @ApiProperty()
  readonly newEmail: string;
}
