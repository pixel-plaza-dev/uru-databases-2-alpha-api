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
    username: string,
    select: Prisma.PasswordResetTokenSelect = { id: true, uuid: true },
  ) {
    return this.user.findUnique({
      where: { username },
      select: {
        passwordResetTokens: {
          where: { expiresAt: { gt: new Date() } },
          select,
        },
      },
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
  ) {
    await this.user.create({
      data: {
        email,
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
        emailVerificationTokens: { create: { email, expiresAt } },
      },
    });
  }

  async createEmailVerificationToken(
    username: string,
    { email, expiresAt }: EmailVerificationTokenCreate,
  ) {
    // Revoke all email verification tokens
    await this.revokeEmailVerificationToken(username, email);

    // Create new email verification token
    return this.emailVerificationToken.create({
      data: { email, expiresAt, user: { connect: { username } } },
    });
  }

  async createPasswordResetToken(
    username: string,
    { email, expiresAt }: PasswordResetTokenCreate,
  ) {
    // Revoke all password reset tokens
    await this.revokePasswordResetToken(username);

    // Create new password reset token
    return this.passwordResetToken.create({
      data: { email, expiresAt, user: { connect: { username } } },
    });
  }

  async createUserLoginAttempt(
    username: string,
    { ip, successful, userAgent }: UserLoginAttemptCreate,
  ) {
    return this.userLoginAttempt.create({
      data: { ip, successful, userAgent, user: { connect: { username } } },
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
  ) {
    await this.user.update({
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
  ) {
    await this.user.update({
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
    await this.revokeJwtRefreshTokens(username);

    // Update user password and add it to history
    await this.user.update({
      where: { username },
      data: { password, passwordHistory: { create: { password } } },
    });
  }

  async updateUsername(username: string, newUsername: string) {
    // Revoke all refresh tokens and its access tokens
    await this.revokeJwtRefreshTokens(username);

    // Update username and add it to history
    await this.user.update({
      where: { username },
      data: {
        username: newUsername,
        usernameHistory: { create: { username: newUsername } },
      },
    });
  }

  async updateUserRoles(
    triggeredByUsername: string,
    targetUsername: string,
    userRoleAction: UserRoleAction,
    roles: Role[],
  ) {
    // Add roles to user
    const updateUser = this.user.update({
      where: { username: targetUsername },
      data: {
        roles: {
          createMany: {
            data: roles.map((role) => ({ role })),
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

  async setJwtRefreshTokenAsUsed(token: string) {
    const currentDateTime = new Date();

    await this.jwtRefreshToken.update({
      where: { token },
      data: {
        usedAt: currentDateTime,
        revokedAt: currentDateTime,
      },
    });
  }

  async revokeJwtAccessToken(token: string) {
    await this.jwtAccessToken.update({
      where: { token },
      data: { revokedAt: new Date() },
    });
  }

  async revokeJwtRefreshToken(refreshToken: string) {
    const revokedAt = new Date();

    // Revoke refresh token
    const revokeRefreshToken = this.jwtRefreshToken.update({
      where: { token: refreshToken, revokedAt: null },
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

  async revokeEmailVerificationToken(username: string, email: string) {
    const revokedAt = new Date();

    await this.user.update({
      where: { username },
      data: {
        emailVerificationTokens: {
          updateMany: {
            where: { email, expiresAt: { gt: revokedAt } },
            data: { revokedAt: new Date() },
          },
        },
      },
    });
  }

  async revokePasswordResetToken(username: string) {
    await this.user.update({
      where: { username },
      data: {
        passwordResetTokens: {
          updateMany: {
            where: { expiresAt: { gt: new Date() } },
            data: { revokedAt: new Date() },
          },
        },
      },
    });
  }

  async deleteUser(username: string) {
    // Revoke all refresh tokens and its access token
    await this.revokeJwtRefreshTokens(username);

    // Delete user
    await this.user.update({
      where: { username },
      data: { deleted: true },
    });
  }
}