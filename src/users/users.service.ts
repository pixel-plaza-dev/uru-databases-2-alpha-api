import { HttpStatus, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UserUpdateDto } from '../dto/user/user-update.dto';
import { UserChangeEmailDto } from '../dto/user/user-change-email.dto';
import { UserChangePasswordDto } from '../dto/user/user-change-password.dto';
import { UserForgotPasswordDto } from '../dto/user/user-forgot-password.dto';
import { UserDeleteDto } from '../dto/user/user-delete';
import { UserUpdateRolesDto } from '../dto/user/user-update-roles.dto';
import { UserCloseAllSessionsDto } from '../dto/user/user-close-all-sessions';
import { Request } from 'express';
import { AuthService } from '../guards/auth/auth.service';
import { REFRESH_TOKEN } from '../global/config';
import {
  USER_DELETED,
  USER_EMAIL_CHANGED,
  USER_FORGOT_PASSWORD,
  USER_LOGOUT,
  USER_NO_PASSWORD_CHANGE,
  USER_NOTHING_TO_UPDATE,
  USER_PASSWORD_CHANGED,
  USER_SESSIONS_CLOSED,
  USER_UPDATED,
  USER_USERNAME_CHANGED,
} from '../global/messages';
import { LoggerService } from '../logger/logger.service';
import {
  UNREGISTERED_USR_ROLE_ACTION,
  USER_PASSWORDS_DO_NOT_MATCH,
  USER_REGISTERED,
  USER_WRONG_CREDENTIALS,
} from '../global/errors';
import { UserChangeUsernameDto } from '../dto/user/user-change-username.dto';
import { UserRoleAction } from '@prisma/client';
import { UserResetPasswordDto } from '../dto/user/user-reset-password.dto';

@Injectable()
export class UsersService {
  private readonly logger = new LoggerService(UsersService.name);

  constructor(
    private prismaService: PrismaService,
    private authService: AuthService,
  ) {}

  async comparePasswords(password: string, confirmPassword: string) {
    return (
      password === confirmPassword ||
      (await this.authService.comparePasswords(password, confirmPassword))
    );
  }

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
    await this.prismaService.updateUser(username, user);

    return this.logger.onUserSuccess(
      USER_UPDATED,
      username,
      HttpStatus.CREATED,
    );
  }

  async changeEmail(req: Request, user: UserChangeEmailDto) {
    const { username } = this.authService.getJwtDataFromRequest(req);
    // HERE, WE SHOULD SEND A TOKEN TO THE GIVEN EMAIL TO VERIFY IT

    return this.logger.onUserSuccess(
      USER_EMAIL_CHANGED,
      username,
      HttpStatus.CREATED,
    );
  }

  async changeSecondaryEmail(req: Request, user: UserChangeEmailDto) {}

  async sendEmailVerificationToken(req: Request) {
    // HERE, WE SHOULD SEND A TOKEN TO THE GIVEN EMAIL TO VERIFY IT
  }

  async verifyEmail(token: string, req: Request) {
    // HERE, WE SHOULD VERIFY THE TOKEN SENT TO THE EMAIL
  }

  async changeUsername(req: Request, { newUsername }: UserChangeUsernameDto) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Check if user exists
    const userExists = await this.prismaService.findUser(username);

    if (userExists) this.logger.onUserBadRequest(USER_REGISTERED, username);

    // Update username
    await this.prismaService.updateUsername(username, newUsername);

    // SEND NOTIFICATION TO EMAIL...

    return this.logger.onUserSuccess(
      USER_USERNAME_CHANGED,
      username,
      HttpStatus.CREATED,
    );
  }

  async changePassword(
    req: Request,
    { password, currentPassword, confirmPassword }: UserChangePasswordDto,
  ) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Verify current password
    await this.authService.verifyUserPassword(username, currentPassword);

    // Compare password with confirm password
    const passwordMatch = await this.comparePasswords(
      password,
      confirmPassword,
    );
    if (!passwordMatch)
      this.logger.onUserBadRequest(USER_PASSWORDS_DO_NOT_MATCH, username);

    // Compare password with current password
    const currentPasswordMatch = await this.comparePasswords(
      currentPassword,
      password,
    );
    if (currentPasswordMatch)
      this.logger.onUserBadRequest(USER_NO_PASSWORD_CHANGE, username);

    // Change user password
    await this.prismaService.updatePassword(username, password);

    // SEND NOTIFICATION TO EMAIL...

    return this.logger.onUserSuccess(
      USER_PASSWORD_CHANGED,
      username,
      HttpStatus.CREATED,
    );
  }

  async forgotPassword({ username, email }: UserForgotPasswordDto) {
    // Generate password reset token
    // NOTE: This method returns a token that should be sent to the user's email
    await this.authService.createPasswordResetToken(username, email);

    // SEND PASSWORD RESET TOKEN TO EMAIL...

    return this.logger.onUserSuccess(
      USER_FORGOT_PASSWORD,
      username,
      HttpStatus.CREATED,
    );
  }

  async resetPassword(token: string, { username, email, password }: UserResetPasswordDto) {}

  async logout(req: Request) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Extract refresh token from request
    const refreshToken = this.authService.extractTokenFromCookies(
      req,
      REFRESH_TOKEN,
    );

    // Revoke refresh token
    await this.prismaService.revokeRefreshToken(refreshToken);

    return this.logger.onUserSuccess(USER_LOGOUT, username);
  }

  async closeAllSessions(req: Request, { password }: UserCloseAllSessionsDto) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Verify user password
    await this.authService.verifyUserPassword(username, password);

    // Revoke all refresh and its access tokens
    await this.prismaService.revokeRefreshTokens(username);

    return this.logger.onUserSuccess(USER_SESSIONS_CLOSED, username);
  }

  async delete(
    req: Request,
    { username: deleteUsername, password, confirmPassword }: UserDeleteDto,
  ) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Compare provided username with token username
    if (username !== deleteUsername)
      this.logger.onUnauthorized(USER_WRONG_CREDENTIALS);

    // Compare password with confirm password
    const passwordMatch = await this.comparePasswords(
      password,
      confirmPassword,
    );
    if (!passwordMatch)
      this.logger.onUserBadRequest(USER_PASSWORDS_DO_NOT_MATCH, username);

    // Verify user password
    await this.authService.verifyUserPassword(username, password);

    // Delete user
    await this.prismaService.deleteUser(username);

    this.logger.onUserSuccess(USER_DELETED, username);
  }

  async updateRoles(
    req: Request,
    userRoleAction: UserRoleAction,
    { username: targetUsername, roles: targetRoles }: UserUpdateRolesDto,
  ) {
    const { username: triggeredByUsername } =
      this.authService.getJwtDataFromRequest(req);

    // Check if the user has some roles
    const userRoles = await this.prismaService.findUserRoles(targetUsername);

    // Extract roles
    const roles = this.authService.extractRoles(userRoles);

    // Filter out roles that are already assigned
    let filteredRoles = [];

    if (userRoleAction === UserRoleAction.ADD)
      filteredRoles = targetRoles.filter((role) => !roles.includes(role));
    else if (userRoleAction === UserRoleAction.REMOVE)
      filteredRoles = targetRoles.filter((role) => roles.includes(role));
    else this.logger.onInternalServerError(UNREGISTERED_USR_ROLE_ACTION);

    // Add roles to user
    await this.prismaService.updateUserRoles(
      triggeredByUsername,
      targetUsername,
      userRoleAction,
      filteredRoles,
    );

    return this.logger.onUserRolesUpdateSuccess(
      triggeredByUsername,
      targetUsername,
      userRoleAction,
      filteredRoles,
    );
  }

  async addRoles(req: Request, { username, roles }: UserUpdateRolesDto) {
    return this.updateRoles(req, UserRoleAction.ADD, { username, roles });
  }

  async removeRoles(req: Request, { username, roles }: UserUpdateRolesDto) {
    return this.updateRoles(req, UserRoleAction.REMOVE, { username, roles });
  }
}
