import { Injectable, OnModuleInit } from '@nestjs/common';
import {
  EmailVerificationToken,
  JwtToken,
  JwtTokenData,
  PasswordResetToken,
  Prisma,
  PrismaClient,
  Role,
  User,
  UserRole,
  UserRoleAction,
} from '@prisma/client';
import { UserUpdateDto } from '../dto/user/user-update.dto';
import { awaitConcurrently } from '../utils/execute-concurrently';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  async onModuleInit() {
    await this.$connect();
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

  async findRefreshJwtToken(
    token: string,
    select: Prisma.JwtTokenSelect = { id: true },
  ) {
    return this.jwtToken.findUnique({
      where: { refreshToken: token },
      select,
    });
  }

  async findAccessToken(
    token: string,
    select: Prisma.JwtTokenSelect = { id: true },
  ) {
    return this.jwtToken.findUnique({
      where: { accessToken: token },
      select,
    });
  }

  async findUserRoles(username: string): Promise<UserRole[]> {
    const { roles } = await this.findUser(username, { roles: true });
    return roles;
  }

  async findUserEmailVerificationToken(
    username: string,
    email: string,
    select: Prisma.EmailVerificationTokenSelect = { id: true, uuid: true },
  ) {
    return this.user.findUnique({
      where: { username },
      select: {
        emailVerificationTokens: {
          where: { email, expiresAt: { gt: new Date() } },
          select,
        },
      },
    });
  }

  findUserPasswordResetToken(
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

  async createUser({
    email,
    username,
    password,
    firstName,
    lastName,
    address,
    phone,
    birthDate,
  }: User) {
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
      },
    });
  }

  async createEmailVerification(
    username: string,
    { email, expiresAt }: EmailVerificationToken,
  ) {
    await this.user.update({
      where: { username },
      data: { emailVerificationTokens: { create: { email, expiresAt } } },
    });
  }

  async createPasswordReset(
    username: string,
    { email, expiresAt }: PasswordResetToken,
  ) {
    await this.user.update({
      where: { username },
      data: { passwordResetTokens: { create: { email, expiresAt } } },
    });
  }

  async createJwtToken(
    username: string,
    { refreshToken, accessToken }: JwtToken,
    { expiresAt: refreshExpiresAt }: JwtTokenData,
    { expiresAt: accessExpiresAt }: JwtTokenData,
  ) {
    await this.user.update({
      where: { username },
      data: {
        jwtTokens: {
          create: {
            refreshToken,
            refreshTokenData: { create: { expiresAt: refreshExpiresAt } },
            accessToken,
            accessTokenData: { create: { expiresAt: accessExpiresAt } },
          },
        },
      },
    });
  }

  async updateUser(username: string, fields: UserUpdateDto) {
    await this.user.update({
      where: { username },
      data: { ...fields },
    });
  }

  async updatePassword(username: string, password: string) {
    // Revoke all refresh tokens and its access tokens
    await this.revokeRefreshTokens(username);

    // Update user password and add it to history
    await this.user.update({
      where: { username },
      data: { password, passwordHistory: { create: { password } } },
    });
  }

  async updateUsername(username: string, newUsername: string) {
    // Revoke all refresh tokens and its access tokens
    await this.revokeRefreshTokens(username);

    // Update username and add it to history
    await this.user.update({
      where: { username },
      data: {
        username: newUsername,
        usernameHistory: { create: { username: newUsername } },
      },
    });
  }

  async addUserRoles(triggeredBy: string, target: string, roles: Role[]) {
    // Add roles to user
    const updateUser = this.user.update({
      where: { username: target },
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
      where: { username: triggeredBy },
      data: {
        triggeredByHistory: {
          create: roles.map((role) => ({
            action: UserRoleAction.ADD,
            target: { connect: { username: target } },
            role,
          })),
        },
      },
    });

    await awaitConcurrently(updateUser, updateRoleHistory);
  }

  async updateAccessTokenLastUsage(accessToken: string) {
    await this.jwtToken.update({
      where: { accessToken },
      data: {
        accessTokenData: { update: { lastUsedAt: new Date() } },
      },
    });
  }

  async revokeRefreshToken(refreshToken: string, revokeAccessToken = false) {
    const revokedAt = new Date();

    // Revoke refresh token
    if (revokeAccessToken)
      return this.jwtToken.update({
        where: { refreshToken },
        data: { refreshTokenData: { update: { revokedAt } } },
      });

    // Revoke refresh token and its access token
    return this.jwtToken.update({
      where: { refreshToken },
      data: {
        refreshTokenData: { update: { revokedAt } },
        accessTokenData: { update: { revokedAt } },
      },
    });
  }

  async revokeRefreshTokens(username: string) {
    const revokedAt = new Date();

    // Revoke all refresh tokens
    const revokeRefreshTokens = this.jwtTokenData.updateMany({
      where: {
        refreshToken: { user: { username } },
        revokedAt: null,
      },
      data: { revokedAt },
    });

    // Revoke all access tokens
    const revokeAccessTokens = this.jwtTokenData.updateMany({
      where: {
        accessToken: { user: { username } },
        revokedAt: null,
      },
      data: { revokedAt },
    });

    await awaitConcurrently(revokeRefreshTokens, revokeAccessTokens);
  }

  async revokeAccessToken(accessToken: string) {
    await this.jwtToken.update({
      where: { accessToken },
      data: { accessTokenData: { update: { revokedAt: new Date() } } },
    });
  }

  async deleteUser(username: string) {
    // Revoke all refresh tokens and its access token
    await this.revokeRefreshTokens(username);

    // Delete user
    await this.user.update({
      where: { username },
      data: { deleted: true },
    });
  }
}
