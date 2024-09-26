import { IsEmail, IsNotEmpty, IsString, MinLength } from 'class-validator';

export class UserDeleteDto {
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
}
