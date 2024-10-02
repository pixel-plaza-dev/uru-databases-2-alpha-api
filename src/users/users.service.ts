import { HttpStatus, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UserUpdateDto } from '../dto/user/user-update.dto';
import { UserChangeEmailDto } from '../dto/user/user-change-email.dto';
import { UserChangePasswordDto } from '../dto/user/user-change-password.dto';
import { UserForgotPasswordDto } from '../dto/user/user-forgot-password.dto';
import { UserDeleteDto } from '../dto/user/user-delete';
import { UserAddRolesDto } from '../dto/user/user-add-roles.dto';
import { UserCloseAllSessionsDto } from '../dto/user/user-close-all-sessions';
import { Request } from 'express';
import { AuthService } from '../auth/auth.service';
import { REFRESH_TOKEN } from '../global/config';
import {
  USER_CHANGED_EMAIL,
  USER_CHANGED_PASSWORD,
  USER_DELETED,
  USER_FORGOT_PASSWORD,
  USER_LOGOUT,
  USER_NOTHING_TO_UPDATE,
  USER_SESSIONS_CLOSED,
  USER_UPDATED,
} from '../global/messages';
import { LoggerService } from '../logger/logger.service';
import { USER_WRONG_CREDENTIALS } from '../global/errors';
import * as https from 'node:https';

@Injectable()
export class UsersService {
  private readonly logger = new LoggerService(UsersService.name);

  constructor(
    private prismaService: PrismaService,
    private authService: AuthService,
  ) {}

  async update(req: Request, user: UserUpdateDto) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Check if there are user fields to update
    if (!Object.keys(user).length)
      this.logger.onUserSuccess(
        USER_NOTHING_TO_UPDATE,
        username,
        HttpStatus.CREATED,
      );

    // Update user fields
    await this.prismaService.updateUser(username, { ...user });

    return this.logger.onUserSuccess(
      USER_UPDATED,
      username,
      HttpStatus.CREATED,
    );
  }

  async changePassword(req: Request, user: UserChangePasswordDto) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Compare

    return this.logger.onUserSuccess(
      USER_CHANGED_PASSWORD,
      username,
      HttpStatus.CREATED,
    );
  }

  async changeEmail(req: Request, user: UserChangeEmailDto) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    return this.logger.onUserSuccess(
      USER_CHANGED_EMAIL,
      username,
      HttpStatus.CREATED,
    );
  }

  async forgotPassword(user: UserForgotPasswordDto) {
    return this.logger.onUserSuccess(
      USER_FORGOT_PASSWORD,
      user.username,
      HttpStatus.CREATED,
    );
  }

  async logout(req: Request) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Extract refresh token from request
    const refreshToken = this.authService.extractTokenFromCookies(
      req,
      REFRESH_TOKEN,
    );

    // Invalidate refresh token
    await this.prismaService.invalidateRefreshToken(refreshToken);

    return this.logger.onUserSuccess(USER_LOGOUT, username);
  }

  async closeAllSessions(req: Request, user: UserCloseAllSessionsDto) {
    const { password } = user;
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Verify user password
    await this.authService.verifyUserPassword(username, password);

    // Invalidate all refresh and access tokens
    await this.prismaService.invalidateRefreshTokens(username);

    return this.logger.onUserSuccess(USER_SESSIONS_CLOSED, username);
  }

  async delete(req: Request, user: UserDeleteDto) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Compare provided username with token username
    if (username !== user.username)
      this.logger.onUnauthorized(USER_WRONG_CREDENTIALS);

    // Verify user password
    await this.authService.verifyUserPassword(username, user.password);

    await (() => {
      // Invalidate all refresh and access tokens
      const p1 = this.prismaService.invalidateRefreshTokens(username);

      // Delete user
      const p2 = this.prismaService.deleteUser(username);

      return Promise.all([p1, p2]);
    })();

    this.logger.onUserSuccess(USER_DELETED, username);
  }

  async addRoles(req: Request, user: UserAddRolesDto) {
    const { username } = this.authService.getJwtDataFromRequest(req);
    const { username: targetUsername } = user;

    // Check if the user has some roles
    const userRoles = await this.prismaService.getUserRoles(targetUsername);

    // Extract roles
    const roles = this.authService.extractRoles(userRoles);

    // Filter out roles that are already assigned
    const filteredRoles = user.roles.filter((role) => !roles.includes(role));

    // Add roles to user
    await this.prismaService.addUserRoles(targetUsername, filteredRoles);

    return this.logger.onUserAddedRolesSuccess(
      username,
      targetUsername,
      filteredRoles,
    );
  }
}
