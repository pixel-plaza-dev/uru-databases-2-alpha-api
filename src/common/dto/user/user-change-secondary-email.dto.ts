import { ApiProperty, PickType } from '@nestjs/swagger';
import { UserDto } from './user.dto';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class UserChangeSecondaryEmailDto extends PickType(UserDto, [
  'username',
] as const) {
  @IsEmail()
  @IsNotEmpty()
  @ApiProperty()
  readonly newSecondaryEmail: string;
}
