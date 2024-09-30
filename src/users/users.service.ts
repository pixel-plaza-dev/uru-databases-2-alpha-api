import { HttpStatus, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UserUpdateDto } from '../dto/user/user-update.dto';
import { UserChangeEmailDto } from '../dto/user/user-change-email.dto';
import { UserChangePasswordDto } from '../dto/user/user-change-password.dto';
import { UserForgotPasswordDto } from '../dto/user/user-forgot-password.dto';
import { UserDeleteDto } from '../dto/user/user-delete';
import { UserChangeRoleDto } from '../dto/user/user-change-role.dto';
import { UserCloseAllSessionsDto } from '../dto/user/user-close-all-sessions';
import { Request } from 'express';
import { AuthService } from '../auth/auth.service';
import { REFRESH_TOKEN } from '../global/config';
import {
  USER_CHANGE_ROLE,
  USER_CHANGED_EMAIL,
  USER_CHANGED_PASSWORD,
  USER_DELETED,
  USER_FORGOT_PASSWORD,
  USER_LOGOUT,
  USER_SESSIONS_CLOSED,
  USER_UPDATED,
} from '../global/messages';
import { LoggerService } from '../logger/logger.service';
import { USER_WRONG_CREDENTIALS } from '../global/errors';

@Injectable()
export class UsersService {
  private readonly logger = new LoggerService(UsersService.name);

  constructor(
    private prismaService: PrismaService,
    private authService: AuthService,
  ) {}

  async update(user: UserUpdateDto) {
    return this.logger.onUserSuccess(
      USER_UPDATED,
      user.email,
      HttpStatus.CREATED,
    );
  }

  async changePassword(user: UserChangePasswordDto) {
    return this.logger.onUserSuccess(
      USER_CHANGED_PASSWORD,
      user.email,
      HttpStatus.CREATED,
    );
  }

  async changeEmail(user: UserChangeEmailDto) {
    return this.logger.onUserSuccess(
      USER_CHANGED_EMAIL,
      user.email,
      HttpStatus.CREATED,
    );
  }

  async forgotPassword(user: UserForgotPasswordDto) {
    return this.logger.onUserSuccess(
      USER_FORGOT_PASSWORD,
      user.email,
      HttpStatus.CREATED,
    );
  }

  async logout(req: Request) {
    const { email } = req['user'];

    // Extract refresh token from request
    const refreshToken = this.authService.extractTokenFromCookies(
      req,
      REFRESH_TOKEN,
    );

    // Invalidate refresh token
    await this.prismaService.invalidateRefreshToken(refreshToken);

    return this.logger.onUserSuccess(USER_LOGOUT, email);
  }

  async closeAllSessions(req: Request, user: UserCloseAllSessionsDto) {
    const { email } = req['user'];

    // Verify password
    const userFound = await this.prismaService.findUser(email, {
      password: true,
      id: true,
    });
    const match = await this.authService.verifyPassword(
      user.password,
      userFound.password,
    );

    if (!match) this.logger.onUnauthorized(USER_WRONG_CREDENTIALS);

    // Invalidate all refresh and access tokens
    await this.prismaService.invalidateRefreshTokens(userFound.id);

    return this.logger.onUserSuccess(USER_SESSIONS_CLOSED, email);
  }

  async delete(user: UserDeleteDto) {
    this.logger.onUserSuccess(USER_DELETED, user.email);
  }

  async changeRole(user: UserChangeRoleDto) {
    this.logger.onUserSuccess(USER_CHANGE_ROLE, user.email);
  }
}
