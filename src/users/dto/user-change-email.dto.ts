import { IsEmail, IsNotEmpty } from 'class-validator';

export class UserChangeEmailDto {
  @IsEmail()
  @IsNotEmpty()
  readonly currentEmail: string;

  @IsEmail()
  @IsNotEmpty()
  readonly email: string;
}
