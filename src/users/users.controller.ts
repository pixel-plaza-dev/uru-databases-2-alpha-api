import { Body, Controller, Delete, Patch, Post } from '@nestjs/common';
import { SignupUserDto } from './dto/user-signup.dto';
import { UsersService } from './users.service';
import { UserLoginDto } from './dto/user-login.dto';
import { UserUpdateDto } from './dto/user-update.dto';
import { UserChangePasswordDto } from './dto/user-change-password.dto';
import { UserChangeEmailDto } from './dto/user-change-email.dto';
import { UserForgotPasswordDto } from './dto/user-forgot-password.dto';
import { UserDeleteDto } from './dto/user-delete';

@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Patch()
  async update(@Body() user: UserUpdateDto) {
    return this.usersService.update(user);
  }

  @Post('signup')
  async signup(@Body() user: SignupUserDto) {
    return this.usersService.signup(user);
  }

  @Post('login')
  async login(@Body() user: UserLoginDto) {
    return this.usersService.login(user);
  }

  @Patch('change-password')
  async changePassword(@Body() user: UserChangePasswordDto) {
    return this.usersService.changePassword(user);
  }

  @Patch('change-email')
  async changeEmail(@Body() user: UserChangeEmailDto) {
    return this.usersService.changeEmail(user);
  }

  @Post('forgot-password')
  async forgotPassword(@Body() user: UserForgotPasswordDto) {
    return this.usersService.forgotPassword(user);
  }

  @Post('logout')
  async logout() {
    return this.usersService.logout();
  }

  @Delete()
  async delete(@Body() user: UserDeleteDto) {
    return this.usersService.delete(user);
  }
}
