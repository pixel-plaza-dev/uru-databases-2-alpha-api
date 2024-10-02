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
import { UserAddRolesDto } from '../dto/user/user-add-roles.dto';
import { AuthGuard } from '../auth/auth.guard';
import { UserCloseAllSessionsDto } from '../dto/user/user-close-all-sessions';
import { Request } from 'express';
import { Public } from 'src/public/public.decorator';
import { Role } from '@prisma/client';
import { Roles } from '../roles/roles.decorator';

@UseGuards(AuthGuard)
@Controller('users')
export class UsersController {
  constructor(private usersService: UsersService) {}

  @Patch()
  async update(@Req() req: Request, @Body() user: UserUpdateDto) {
    return this.usersService.update(req, user);
  }

  @Patch('change-password')
  async changePassword(
    @Req() req: Request,
    @Body() user: UserChangePasswordDto,
  ) {
    return this.usersService.changePassword(req, user);
  }

  @Patch('change-email')
  async changeEmail(@Req() req: Request, @Body() user: UserChangeEmailDto) {
    return this.usersService.changeEmail(req, user);
  }

  @Public()
  @Post('forgot-password')
  async forgotPassword(@Body() user: UserForgotPasswordDto) {
    return this.usersService.forgotPassword(user);
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

  @Roles(Role.ADMIN)
  @Post('add-roles')
  async setAdmin(@Req() req: Request, @Body() user: UserAddRolesDto) {
    return this.usersService.addRoles(req, user);
  }
}
