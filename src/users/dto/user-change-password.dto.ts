import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class UserChangePasswordDto {
  @IsEmail()
  @IsNotEmpty()
  readonly email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(12)
  readonly currentPassword: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(12)
  readonly password: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(12)
  readonly confirmPassword: string;
}
