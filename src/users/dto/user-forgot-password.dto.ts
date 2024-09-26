import { IsEmail, IsNotEmpty } from 'class-validator';

export class UserForgotPasswordDto {
  @IsEmail()
  @IsNotEmpty()
  readonly email: string;
}
