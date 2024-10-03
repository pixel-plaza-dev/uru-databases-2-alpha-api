import { ApiProperty } from '@nestjs/swagger';
import { IsAlphanumeric, IsNotEmpty, MaxLength } from 'class-validator';

export class UserChangeUsernameDto {
  @IsAlphanumeric()
  @IsNotEmpty()
  @ApiProperty()
  @MaxLength(64)
  readonly newUsername: string;
}
