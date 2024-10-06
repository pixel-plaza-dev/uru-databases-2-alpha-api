import { IsNotEmpty, IsString, MaxLength, MinLength } from 'class-validator';
import { ApiProperty, PickType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class UserChangePasswordDto extends PickType(UserDto, [
  'password',
  'confirmPassword',
] as const) {
  @IsString()
  @IsNotEmpty()
  @MinLength(12)
  @MaxLength(64)
  @ApiProperty()
  readonly currentPassword: string;
}
