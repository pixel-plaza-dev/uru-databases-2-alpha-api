import { Injectable, Logger } from '@nestjs/common';
import { SignupUserDto } from './dto/user-signup.dto';
import { UserLoginDto } from './dto/user-login.dto';
import { UserUpdateDto } from './dto/user-update.dto';
import { UserChangePasswordDto } from './dto/user-change-password.dto';
import { UserChangeEmailDto } from './dto/user-change-email.dto';
import { UserForgotPasswordDto } from './dto/user-forgot-password.dto';
import { UserDeleteDto } from './dto/user-delete';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  async update(user: UserUpdateDto) {
    this.logger.log('User update: ' + user.email);
    return user;
  }

  async signup(user: SignupUserDto) {
    this.logger.log('User signup: ' + user.email);
    return user;
  }

  async login(user: UserLoginDto) {
    this.logger.log('User login: ' + user.email);
    return user;
  }

  async changePassword(user: UserChangePasswordDto) {
    this.logger.log('User change password: ' + user.email);
    return user;
  }

  async changeEmail(user: UserChangeEmailDto) {
    this.logger.log('User change email: ' + user.email);
    return user;
  }

  async forgotPassword(user: UserForgotPasswordDto) {
    this.logger.log('User forgot password: ' + user.email);
    return user;
  }

  async logout() {
    this.logger.log('User logout');
    return 'User logout';
  }

  async delete(user: UserDeleteDto) {
    this.logger.log('User delete: ' + user.email);
    return user;
  }
}
