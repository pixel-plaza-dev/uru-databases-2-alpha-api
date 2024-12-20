import {
  Body,
  Controller,
  Delete,
  Param,
  Patch,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { UsersService } from './users.service';
import { UserUpdateDto } from '../common/dto/user/user-update.dto';
import { UserChangePasswordDto } from '../common/dto/user/user-change-password.dto';
import { UserChangeEmailDto } from '../common/dto/user/user-change-email.dto';
import { UserForgotPasswordDto } from '../common/dto/user/user-forgot-password.dto';
import { UserDeleteDto } from '../common/dto/user/user-delete';
import { UserUpdateRolesDto } from '../common/dto/user/user-update-roles.dto';
import { AuthGuard } from '../common/guards/auth/auth.guard';
import { UserCloseAllSessionsDto } from '../common/dto/user/user-close-all-sessions';
import { Request } from 'express';
import { Public } from 'src/common/decorators/public.decorator';
import { Role } from '@prisma/client';
import { Roles } from '../common/decorators/roles.decorator';
import { UserChangeUsernameDto } from '../common/dto/user/user-change-username.dto';
import { UserResetPasswordDto } from '../common/dto/user/user-reset-password.dto';
import { UserSendEmailVerificationTokenDto } from '../common/dto/user/user-send-email-verification-token.dto';

@UseGuards(AuthGuard)
@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Patch()
  async update(@Req() req: Request, @Body() user: UserUpdateDto) {
    return this.usersService.update(req, user);
  }

  @Patch('username')
  async updateUsername(
    @Req() req: Request,
    @Body() user: UserChangeUsernameDto,
  ) {
    return this.usersService.changeUsername(req, user);
  }

  @Patch('password')
  async changePassword(
    @Req() req: Request,
    @Body() user: UserChangePasswordDto,
  ) {
    return this.usersService.changePassword(req, user);
  }

  @Patch('email')
  async changeEmail(@Req() req: Request, @Body() user: UserChangeEmailDto) {
    return this.usersService.changeEmail(req, user);
  }

  @Post('verify-email')
  async sendEmailVerificationToken(
    @Req() req: Request,
    @Body() user: UserSendEmailVerificationTokenDto,
  ) {
    return this.usersService.sendEmailVerificationToken(req, user);
  }

  @Post('verify-email/:uuid')
  async verifyEmail(@Param('uuid') uuid: string) {
    return this.usersService.verifyEmail(uuid);
  }

  @Public()
  @Post('forgot-password')
  async forgotPassword(@Body() user: UserForgotPasswordDto) {
    return this.usersService.forgotPassword(user);
  }

  @Public()
  @Post('reset-password/:uuid')
  async resetPassword(
    @Param('uuid') uuid: string,
    @Body() user: UserResetPasswordDto,
  ) {
    return this.usersService.resetPassword(uuid, user);
  }

  @Post('logout')
  async logout(@Req() req: Request) {
    return this.usersService.logout(req);
  }

  @Post('close-all-sessions')
  async closeAllSessions(
    @Req() req: Request,
    @Body() user: UserCloseAllSessionsDto,
  ) {
    return this.usersService.closeAllSessions(req, user);
  }

  @Delete()
  async delete(@Req() req: Request, @Body() user: UserDeleteDto) {
    return this.usersService.delete(req, user);
  }

  @Roles(Role.MALL_MANAGER, Role.MALL_OWNER)
  @Post('add-roles')
  async addRoles(@Req() req: Request, @Body() user: UserUpdateRolesDto) {
    return this.usersService.addRoles(req, user);
  }

  @Roles(Role.MALL_MANAGER, Role.MALL_OWNER)
  @Post('remove-roles')
  async removeRoles(@Req() req: Request, @Body() user: UserUpdateRolesDto) {
    return this.usersService.removeRoles(req, user);
  }
}
