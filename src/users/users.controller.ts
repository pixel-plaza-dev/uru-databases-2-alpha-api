import {
  Body,
  Controller,
  Delete,
  Patch,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { UserUpdateDto } from '../dto/user/user-update.dto';
import { UserChangePasswordDto } from '../dto/user/user-change-password.dto';
import { UserChangeEmailDto } from '../dto/user/user-change-email.dto';
import { UserForgotPasswordDto } from '../dto/user/user-forgot-password.dto';
import { UserDeleteDto } from '../dto/user/user-delete';
import { UserChangeRoleDto } from '../dto/user/user-change-role.dto';
import { AuthGuard } from '../auth/auth.guard';
import { UserCloseAllSessionsDto } from '../dto/user/user-close-all-sessions';
import { Request } from 'express';

@UseGuards(AuthGuard)
@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Patch()
  async update(@Body() user: UserUpdateDto) {
    return this.usersService.update(user);
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

  @Post('close-all-sessions')
  async closeAllSessions(
    @Req() req: Request,
    @Body() user: UserCloseAllSessionsDto,
  ) {
    return this.usersService.closeAllSessions(req, user);
  }

  @Delete()
  async delete(@Body() user: UserDeleteDto) {
    return this.usersService.delete(user);
  }

  @Post('change-role')
  async setAdmin(@Body() user: UserChangeRoleDto) {
    return this.usersService.changeRole(user);
  }
}
