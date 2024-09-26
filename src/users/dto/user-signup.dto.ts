import {
  IsEmail,
  IsNotEmpty,
  IsNumberString,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class SignupUserDto {
  @IsEmail()
  @IsNotEmpty()
  readonly email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(12)
  readonly password: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(12)
  readonly confirmPassword: string;

  @IsString()
  @IsNotEmpty()
  readonly name: string;

  @IsOptional()
  @IsString()
  @MaxLength(100)
  readonly address?: string;

  @IsOptional()
  @IsNumberString()
  readonly phone?: string;
}
