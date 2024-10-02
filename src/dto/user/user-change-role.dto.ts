import { ApiProperty, PickType } from '@nestjs/swagger';
import { IsEnum } from 'class-validator';
import { Role } from '@prisma/client';
import { UserDto } from './user.dto';

export class UserChangeRoleDto extends PickType(UserDto, [
  'username',
] as const) {
  @IsEnum(Role)
  @ApiProperty()
  readonly role: string;
}
