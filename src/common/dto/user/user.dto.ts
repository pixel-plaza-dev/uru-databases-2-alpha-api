import {
  IsAlphanumeric,
  IsDate,
  IsEmail,
  IsNotEmpty,
  IsNumberString,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class UserDto {
  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  readonly id: string;

  @IsEmail()
  @IsNotEmpty()
  @ApiProperty()
  readonly email: string;

  @IsOptional()
  @IsEmail()
  @IsNotEmpty()
  @ApiPropertyOptional()
  readonly secondaryEmail: string;

  @IsAlphanumeric()
  @IsNotEmpty()
  @ApiProperty()
  @MaxLength(64)
  readonly username: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(12)
  @MaxLength(64)
  @ApiProperty()
  readonly password: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(12)
  @MaxLength(64)
  @ApiProperty()
  readonly confirmPassword: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  readonly firstName: string;

  @IsString()
  @IsNotEmpty()
  @ApiProperty()
  readonly lastName: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  @ApiPropertyOptional()
  readonly address?: string;

  @IsOptional()
  @IsNumberString()
  @ApiPropertyOptional()
  readonly phone?: string;

  @IsOptional()
  @IsDate()
  @ApiPropertyOptional()
  readonly birthDate?: Date;
}
