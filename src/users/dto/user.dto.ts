import {
  IsEmail,
  IsNotEmpty,
  IsNumberString,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class UserDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  readonly id: string;

  @IsEmail()
  @IsNotEmpty()
  @ApiProperty()
  readonly email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(12)
  @ApiProperty()
  readonly password: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(12)
  @ApiProperty()
  readonly confirmPassword: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  readonly name: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  @ApiProperty()
  readonly address?: string;

  @IsOptional()
  @IsNumberString()
  @ApiProperty()
  readonly phone?: string;
}
