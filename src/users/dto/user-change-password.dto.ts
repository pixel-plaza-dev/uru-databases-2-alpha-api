import { IsNotEmpty, IsString, MinLength } from 'class-validator';
import { ApiProperty, PickType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class UserChangePasswordDto extends PickType(UserDto, [
  'email',
  'password',
  'confirmPassword',
] as const) {
  @IsString()
  @IsNotEmpty()
  @MinLength(12)
  @ApiProperty()
  readonly currentPassword: string;
}
