import { ApiProperty, PickType } from '@nestjs/swagger';
import { IsEnum } from 'class-validator';
import { Role } from '@prisma/client';
import { UserDto } from './user.dto';

export class UserUpdateRolesDto extends PickType(UserDto, [
  'username',
] as const) {
  @IsEnum(Role, { each: true })
  @ApiProperty({ enum: Role, isArray: true })
  readonly roles: Role[];
}
