import { HttpStatus, Injectable } from '@nestjs/common';
import { PrismaService } from '../common/providers/prisma/prisma.service';
import { UserUpdateDto } from '../common/dto/user/user-update.dto';
import { UserChangeEmailDto } from '../common/dto/user/user-change-email.dto';
import { UserChangePasswordDto } from '../common/dto/user/user-change-password.dto';
import { UserForgotPasswordDto } from '../common/dto/user/user-forgot-password.dto';
import { UserDeleteDto } from '../common/dto/user/user-delete';
import { UserUpdateRolesDto } from '../common/dto/user/user-update-roles.dto';
import { UserCloseAllSessionsDto } from '../common/dto/user/user-close-all-sessions';
import { Request } from 'express';
import { AuthService } from '../common/guards/auth/auth.service';
import { LoggerService } from '../common/providers/logger/logger.service';
import { UserChangeUsernameDto } from '../common/dto/user/user-change-username.dto';
import { UserRoleAction } from '@prisma/client';
import { UserResetPasswordDto } from '../common/dto/user/user-reset-password.dto';
import { REFRESH_TOKEN } from '../config/jwt-token';
import { USER } from '../common/constants/user';
import { TOKEN } from '../common/constants/token';
import { PRISMA } from '../common/constants/prisma';
import { USER_ROLE } from '../common/constants/user-role';

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
      (await this.authService.bcryptComparePasswords(password, confirmPassword))
    );
  }

  async update(req: Request, user: UserUpdateDto) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Check if there are user fields to update
    if (!Object.keys(user).length)
      this.logger.onUserSuccess(
        USER.NOTHING_TO_UPDATE,
        username,
        HttpStatus.CREATED,
      );

    // Update user fields
    await this.prismaService.updateUser(username, user);

    return this.logger.onUserSuccess(
      USER.UPDATED,
      username,
      HttpStatus.CREATED,
    );
  }

  async changeEmail(req: Request, user: UserChangeEmailDto) {
    const { username } = this.authService.getJwtDataFromRequest(req);
    // HERE, WE SHOULD SEND A JwtToken TO THE GIVEN EMAIL TO VERIFY IT

    return this.logger.onUserSuccess(
      USER.EMAIL_CHANGED,
      username,
      HttpStatus.CREATED,
    );
  }

  async changeSecondaryEmail(req: Request, user: UserChangeEmailDto) {}

  async sendEmailVerificationToken(req: Request) {
    // HERE, WE SHOULD SEND A JwtToken TO THE GIVEN EMAIL TO VERIFY IT
  }

  async verifyEmail(token: string, req: Request) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Check if the token is valid
    const emailVerificationToken =
      await this.prismaService.findUserEmailVerificationToken(token, {
        expiresAt: true,
        revokedAt: true,
      });

    if (!emailVerificationToken)
      this.logger.onUserBadRequest(TOKEN.INVALID, username);
    if (emailVerificationToken.revokedAt)
      this.logger.onUserBadRequest(TOKEN.REVOKED, username);

    // HERE, WE SHOULD VERIFY THE JwtToken SENT TO THE EMAIL
  }

  async changeUsername(req: Request, { newUsername }: UserChangeUsernameDto) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    try {
      // Update username
      await this.prismaService.updateUsername(username, newUsername);
    } catch (error) {
      // Check if user exists
      if (error.code === PRISMA.UNIQUE_CONSTRAINT_FAILED)
        this.logger.onUserBadRequest(USER.REGISTERED, username);

      this.logger.onInternalServerError(error.message);
    }

    // SEND NOTIFICATION TO EMAIL...

    return this.logger.onUserSuccess(
      USER.USERNAME_CHANGED,
      username,
      HttpStatus.CREATED,
    );
  }

  async changePassword(
    req: Request,
    { currentPassword, password, confirmPassword }: UserChangePasswordDto,
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
      this.logger.onUserBadRequest(USER.PASSWORDS_DO_NOT_MATCH, username);

    // Compare password with current password
    const currentPasswordMatch = await this.comparePasswords(
      currentPassword,
      password,
    );
    if (currentPasswordMatch)
      this.logger.onUserBadRequest(USER.NO_PASSWORD_CHANGE, username);

    // Change user password
    await this.prismaService.updatePassword(username, password);

    // SEND NOTIFICATION TO EMAIL...

    return this.logger.onUserSuccess(
      USER.PASSWORD_CHANGED,
      username,
      HttpStatus.CREATED,
    );
  }

  async forgotPassword({ username, email }: UserForgotPasswordDto) {
    // Generate password reset token
    // NOTE: This method returns a token that should be sent to the user's email
    await this.authService.createPasswordResetToken(username, email);

    // SEND PASSWORD RESET JwtToken TO EMAIL...

    return this.logger.onUserSuccess(
      USER.FORGOT_PASSWORD,
      username,
      HttpStatus.CREATED,
    );
  }

  async resetPassword(
    token: string,
    { username, email, password }: UserResetPasswordDto,
  ) {}

  async logout(req: Request) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Extract refresh token from request
    const refreshToken = this.authService.extractTokenFromCookies(
      req,
      REFRESH_TOKEN,
    );

    // Revoke refresh token
    await this.prismaService.revokeJwtRefreshToken(refreshToken);

    return this.logger.onUserSuccess(USER.LOGOUT, username);
  }

  async closeAllSessions(req: Request, { password }: UserCloseAllSessionsDto) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Verify user password
    await this.authService.verifyUserPassword(username, password);

    // Revoke all refresh and its access tokens
    await this.prismaService.revokeJwtRefreshTokens(username);

    return this.logger.onUserSuccess(USER.SESSIONS_CLOSED, username);
  }

  async delete(
    req: Request,
    { username: deleteUsername, password, confirmPassword }: UserDeleteDto,
  ) {
    const { username } = this.authService.getJwtDataFromRequest(req);

    // Compare provided username with token username
    if (username !== deleteUsername)
      this.logger.onUnauthorized(USER.WRONG_CREDENTIALS);

    // Compare password with confirm password
    const passwordMatch = await this.comparePasswords(
      password,
      confirmPassword,
    );
    if (!passwordMatch)
      this.logger.onUserBadRequest(USER.PASSWORDS_DO_NOT_MATCH, username);

    // Verify user password
    await this.authService.verifyUserPassword(username, password);

    // Delete user
    await this.prismaService.deleteUser(username);

    this.logger.onUserSuccess(USER.DELETED, username);
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
    else this.logger.onInternalServerError(USER_ROLE.UNREGISTERED_ACTION);

    // Update user roles
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
