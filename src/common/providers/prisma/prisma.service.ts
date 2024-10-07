import {
  Injectable,
  Logger,
  OnModuleDestroy,
  OnModuleInit,
} from '@nestjs/common';
import {
  Prisma,
  PrismaClient,
  Role,
  UserLoginAttempt,
  UserRole,
  UserRoleAction,
} from '@prisma/client';
import { awaitConcurrently } from '../../utils/execute-concurrently';
import { UserCreate, UserUpdate } from './types/user';
import {
  EmailVerificationTokenCreate,
  EmailVerificationTokenSignup,
} from './types/email-verification-token';
import { PasswordResetTokenCreate } from './types/password-reset-token';
import { JwtRefreshTokenCreate } from './types/jwt-refresh-token-data';
import { JwtAccessTokenCreate } from './types/jwt-access-token';
import { UserLoginAttemptCreate } from './types/user-login-attempt';
import { PRISMA } from '../../constants/prisma';

@Injectable()
export class PrismaService
  extends PrismaClient
  implements OnModuleInit, OnModuleDestroy
{
  private readonly logger = new Logger(PrismaService.name);

  async onModuleInit() {
    this.logger.warn(PRISMA.CONNECTING);
    await this.$connect();
    this.logger.log(PRISMA.CONNECTED);
  }

  async onModuleDestroy() {
    this.logger.warn(PRISMA.DISCONNECTING);
    await this.$disconnect();
    this.logger.log(PRISMA.DISCONNECTED);
  }

  async findUser(
    username: string,
    select: Prisma.UserSelect = {
      id: true,
    },
  ) {
    return this.user.findUnique({
      where: { username },
      select,
    });
  }

  async findUserById(
    id: string,
    select: Prisma.UserSelect = {
      id: true,
    },
  ) {
    return this.user.findUnique({
      where: { id },
      select,
    });
  }

  async findUserEmails(
    username: string,
    select: Prisma.UserEmailSelect = {
      email: true,
    },
  ) {
    return this.userEmail.findMany({
      where: { user: { username } },
      select,
    });
  }

  async findJwtRefreshToken(
    token: string,
    select: Prisma.JwtRefreshTokenSelect = { id: true },
  ) {
    return this.jwtRefreshToken.findUnique({
      where: { token },
      select,
    });
  }

  async findJwtAccessToken(
    token: string,
    select: Prisma.JwtAccessTokenSelect = { id: true },
  ) {
    // Find access token
    const tokenFound = await this.jwtAccessToken.findUnique({
      where: { token },
      select,
    });

    // Update access token last used at date
    if (tokenFound) await this.updateJwtAccessTokenLastUsage(token);

    return tokenFound;
  }

  async findUserRoles(username: string): Promise<UserRole[]> {
    const { roles } = await this.findUser(username, { roles: true });
    return roles;
  }

  async findUserEmailVerificationToken(
    uuid: string,
    select: Prisma.EmailVerificationTokenSelect = { id: true },
  ) {
    return this.emailVerificationToken.findUnique({
      where: { uuid },
      select,
    });
  }

  async findUserPasswordResetToken(
    uuid: string,
    select: Prisma.PasswordResetTokenSelect = { id: true, uuid: true },
  ) {
    return this.passwordResetToken.findUnique({
      where: { uuid },
      select,
    });
  }

  async createUser(
    {
      email,
      username,
      password,
      firstName,
      lastName,
      address,
      phone,
      birthDate,
    }: UserCreate,
    { expiresAt }: EmailVerificationTokenSignup,
    select: Prisma.UserSelect = { id: true },
  ) {
    return this.user.create({
      data: {
        emails: {
          create: {
            email,
            isActive: true,
            emailVerificationTokens: { create: { expiresAt } },
          },
        },
        username,
        password,
        firstName,
        lastName,
        address: address ?? Prisma.skip,
        phone: phone ?? Prisma.skip,
        birthDate: birthDate ?? Prisma.skip,
        roles: { create: { role: Role.USER } },
        usernameHistory: { create: { username } },
        passwordHistory: { create: { password } },
      },
      select,
    });
  }

  async createEmailVerificationToken(
    username: string,
    email: string,
    { expiresAt }: EmailVerificationTokenCreate,
    select: Prisma.EmailVerificationTokenSelect = { id: true },
  ) {
    return this.emailVerificationToken.create({
      data: {
        userEmail: { connect: { user: { username }, email, isActive: true } },
        expiresAt,
      },
      select,
    });
  }

  async createPasswordResetToken(
    username: string,
    { email, expiresAt }: PasswordResetTokenCreate,
    select: Prisma.PasswordResetTokenSelect = { id: true },
  ) {
    return this.passwordResetToken.create({
      data: {
        expiresAt,
        userEmail: { connect: { user: { username }, email } },
      },
      select,
    });
  }

  async createUserLoginAttempt(
    username: string,
    { ip, successful, userAgent }: UserLoginAttemptCreate,
    select: Prisma.UserLoginAttemptSelect = { id: true },
  ) {
    return this.userLoginAttempt.create({
      data: { ip, successful, userAgent, user: { connect: { username } } },
      select,
    });
  }

  async createJwtRefreshTokenFromLogin(
    username: string,
    userLoginAttempt: UserLoginAttempt,
    {
      token: refreshToken,
      expiresAt: refreshTokenExpiresAt,
    }: JwtRefreshTokenCreate,
    {
      token: accessToken,
      expiresAt: accessTokenExpiresAt,
    }: JwtAccessTokenCreate,
    select: Prisma.JwtRefreshTokenSelect = { id: true },
  ) {
    return this.user.update({
      where: { username },
      data: {
        jwtRefreshTokens: {
          create: {
            token: refreshToken,
            expiresAt: refreshTokenExpiresAt,
            userLoginAttempt: { connect: { id: userLoginAttempt.id } },
            jwtAccessToken: {
              create: { token: accessToken, expiresAt: accessTokenExpiresAt },
            },
          },
        },
      },
      select,
    });
  }

  async createJwtRefreshTokenFromRefresh(
    username: string,
    parentRefreshToken: string,
    {
      token: refreshToken,
      expiresAt: refreshTokenExpiresAt,
    }: JwtRefreshTokenCreate,
    {
      token: accessToken,
      expiresAt: accessTokenExpiresAt,
    }: JwtAccessTokenCreate,
    select: Prisma.JwtRefreshTokenSelect = { id: true },
  ) {
    return this.user.update({
      where: { username },
      data: {
        jwtRefreshTokens: {
          create: {
            token: refreshToken,
            expiresAt: refreshTokenExpiresAt,
            parentJwtRefreshToken: { connect: { token: parentRefreshToken } },
            jwtAccessToken: {
              create: { token: accessToken, expiresAt: accessTokenExpiresAt },
            },
          },
        },
      },
      select,
    });
  }

  async updateUser(username: string, fields: UserUpdate) {
    await this.user.update({
      where: { username },
      data: { ...fields },
    });
  }

  async updatePassword(username: string, password: string) {
    // Revoke all refresh tokens and its access tokens
    const revokeJwtRefreshTokens = this.revokeJwtRefreshTokens(username);

    // Revoke all password reset tokens
    const revokePasswordResetTokens = this.revokePasswordResetTokens(username);

    // Update user password and add it to history
    const userUpdate = this.user.update({
      where: { username },
      data: {
        password,
        passwordHistory: { create: { password } },
      },
    });

    await awaitConcurrently(
      revokeJwtRefreshTokens,
      revokePasswordResetTokens,
      userUpdate,
    );
  }

  async updateUsername(username: string, newUsername: string) {
    // Revoke all refresh tokens and its access tokens
    const revokeJwtRefreshTokens = this.revokeJwtRefreshTokens(username);

    // Update username and add it to history. Also, revoke all email verification tokens and password reset tokens
    const updateUsername = this.user.update({
      where: { username },
      data: {
        username: newUsername,
        usernameHistory: { create: { username: newUsername } },
      },
    });

    await awaitConcurrently(revokeJwtRefreshTokens, updateUsername);
  }

  async updateEmail(username: string, email: string, newEmail: string) {
    // Set email as inactive
    const setEmailAsInactive = this.setEmailAsInactive(username, email);

    // Update email and add it to history
    const updateUser = this.user.update({
      where: { username },
      data: {
        emails: {
          create: {
            email: newEmail,
            isActive: true,
            emailVerificationTokens: { create: {} },
          },
        },
      },
    });

    await awaitConcurrently(setEmailAsInactive, updateUser);
  }

  async updateUserRoles(
    triggeredByUsername: string,
    targetUsername: string,
    userRoleAction: UserRoleAction,
    roles: Role[],
  ) {
    // Update roles to user
    let updateUser: Promise<any>;

    // Add roles to user
    if (userRoleAction === UserRoleAction.ADD)
      updateUser = this.user.update({
        where: { username: targetUsername },
        data: {
          roles: {
            createMany: {
              data: roles.map((role) => ({ role })),
            },
          },
        },
      });
    // Remove roles from user
    else if (userRoleAction === UserRoleAction.REMOVE)
      updateUser = this.user.update({
        where: { username: targetUsername },
        data: {
          roles: {
            deleteMany: {
              role: { in: roles },
            },
          },
        },
      });

    // Add roles to history
    const updateRoleHistory = this.user.update({
      where: { username: triggeredByUsername },
      data: {
        triggeredByHistory: {
          create: roles.map((role) => ({
            action: userRoleAction,
            target: { connect: { username: targetUsername } },
            role,
          })),
        },
      },
    });

    await awaitConcurrently(updateUser, updateRoleHistory);
  }

  async updateJwtAccessTokenLastUsage(token: string) {
    await this.jwtAccessToken.update({
      where: { token },
      data: {
        lastUsedAt: new Date(),
      },
    });
  }

  async setEmailAsInactive(username: string, email: string) {
    await this.userEmail.updateMany({
      where: { user: { username }, email },
      data: {
        isActive: false,
      },
    });
  }

  async setJwtRefreshTokenAsUsed(token: string) {
    const currentDateTime = new Date();

    await this.jwtRefreshToken.update({
      where: { token, usedAt: null },
      data: {
        usedAt: currentDateTime,
      },
    });
  }

  async setEmailVerificationTokenAsVerified(token: string) {
    // Update user email as verified
    const emailVerificationToken = await this.emailVerificationToken.update({
      where: { uuid: token },
      data: { verifiedAt: new Date() },
      select: {
        userEmail: { select: { user: { select: { username: true } } } },
      },
    });

    const { username } = emailVerificationToken.userEmail.user;

    // Revoke all email verification tokens
    await this.revokeEmailVerificationTokens(username);
  }

  async setPasswordResetTokenAsUsed(token: string) {
    // Update password reset token as used
    const passwordResetToken = await this.passwordResetToken.update({
      where: { uuid: token },
      data: { usedAt: new Date() },
      select: {
        userEmail: { select: { user: { select: { username: true } } } },
      },
    });

    const { username } = passwordResetToken.userEmail.user;

    // Revoke all password reset tokens
    await this.revokePasswordResetTokens(username);
  }

  async revokeJwtAccessToken(token: string) {
    const revokedAt = new Date();

    await this.jwtAccessToken.update({
      where: { token, revokedAt: null, expiresAt: { gt: revokedAt } },
      data: { revokedAt: revokedAt },
    });
  }

  async revokeJwtRefreshToken(refreshToken: string) {
    const revokedAt = new Date();

    // Revoke refresh token
    const revokeRefreshToken = this.jwtRefreshToken.update({
      where: {
        token: refreshToken,
        revokedAt: null,
        expiresAt: { gt: revokedAt },
      },
      data: {
        revokedAt,
      },
    });

    // Revoke access tokens
    const revokeAccessTokens = this.jwtAccessToken.updateMany({
      where: { jwtRefreshToken: { token: refreshToken }, revokedAt: null },
      data: {
        revokedAt,
      },
    });

    await awaitConcurrently(revokeRefreshToken, revokeAccessTokens);
  }

  async revokeJwtRefreshTokens(username: string) {
    const revokedAt = new Date();

    // Revoke all refresh tokens
    const revokeRefreshTokens = this.jwtRefreshToken.updateMany({
      where: {
        user: { username },
        revokedAt: null,
        expiresAt: { gt: revokedAt },
      },
      data: {
        revokedAt,
      },
    });

    // Revoke all access tokens
    const revokeAccessTokens = this.jwtAccessToken.updateMany({
      where: {
        jwtRefreshToken: { user: { username } },
        revokedAt: null,
      },
      data: {
        revokedAt,
      },
    });

    await awaitConcurrently(revokeRefreshTokens, revokeAccessTokens);
  }

  async revokeEmailVerificationTokens(username: string) {
    const revokedAt = new Date();

    await this.emailVerificationToken.updateMany({
      where: {
        verifiedAt: null,
        revokedAt: null,
        expiresAt: { gt: revokedAt },
        userEmail: { user: { username } },
      },
      data: {
        revokedAt,
      },
    });
  }

  async revokePasswordResetTokens(username: string) {
    const revokedAt = new Date();

    await this.passwordResetToken.updateMany({
      where: {
        usedAt: null,
        revokedAt: null,
        expiresAt: { gt: revokedAt },
        userEmail: { user: { username } },
      },
      data: {
        revokedAt,
      },
    });
  }

  async deleteUser(username: string) {
    // Revoke all refresh tokens and its access token
    const revokeJwtRefreshTokens = this.revokeJwtRefreshTokens(username);

    // Revoke all email verification tokens
    const revokeEmailVerificationTokens =
      this.revokeEmailVerificationTokens(username);

    // Revoke all password reset tokens
    const revokePasswordResetTokens = this.revokePasswordResetTokens(username);

    // Delete user
    const deleteUser = this.user.update({
      where: { username },
      data: {
        deleted: true,
      },
    });

    await awaitConcurrently(
      revokeJwtRefreshTokens,
      revokeEmailVerificationTokens,
      revokePasswordResetTokens,
      deleteUser,
    );
  }
}
