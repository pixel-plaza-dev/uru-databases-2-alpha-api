import { Injectable, OnModuleInit } from '@nestjs/common';
import { Prisma, PrismaClient, Role, UserRole } from '@prisma/client';
import { RefreshTokenCreate } from './interfaces/refresh-token';
import { AccessTokenCreate } from './interfaces/access-token';
import { UserUpdateDto } from '../dto/user/user-update.dto';
import { UserAuthSignupDto } from '../dto/user/auth/user-auth-signup.dto';

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

  async findRefreshToken(
    token: string,
    select: Prisma.RefreshTokenSelect = { id: true },
  ) {
    return this.refreshToken.findUnique({
      where: { token },
      select,
    });
  }

  async findAccessToken(
    token: string,
    select: Prisma.AccessTokenSelect = { id: true },
  ) {
    return this.accessToken.findUnique({
      where: { token },
      select,
    });
  }

  async getUserRoles(username: string): Promise<UserRole[]> {
    const { roles } = await this.findUser(username, { roles: true });
    return roles;
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
  }: UserAuthSignupDto) {
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
      },
    });
  }

  async addUserRoles(username: string, roles: Role[]) {
    await this.user.update({
      where: { username },
      data: {
        roles: {
          createMany: {
            data: roles.map((role) => ({ role })),
          },
        },
      },
    });
  }

  async createRefreshToken({ username, token, expiresAt }: RefreshTokenCreate) {
    await this.user.update({
      where: { username },
      data: { refreshTokens: { create: { token, expiresAt } } },
    });
  }

  async createAccessToken({
    token,
    expiresAt,
    refreshToken,
  }: AccessTokenCreate) {
    await this.refreshToken.update({
      where: { token: refreshToken },
      data: {
        accessToken: {
          create: {
            token,
            expiresAt,
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

  async updateAccessTokenLastUsage(token: string) {
    await this.accessToken.update({
      where: { token },
      data: { lastUsedAt: new Date() },
    });
  }

  async invalidateRefreshToken(token: string) {
    const revokedAt = new Date();

    await this.refreshToken.updateMany({
      where: { token },
      data: { revokedAt },
    });
    await this.accessToken.updateMany({
      where: { refreshToken: { token } },
      data: { revokedAt },
    });
  }

  async invalidateRefreshTokens(username: string) {
    const revokedAt = new Date();

    await this.refreshToken.updateMany({
      where: { user: { username } },
      data: { revokedAt },
    });
    await this.accessToken.updateMany({
      where: {
        refreshToken: {
          user: { username },
        },
      },
      data: { revokedAt },
    });
  }

  async invalidateAccessToken(token: string) {
    await this.accessToken.update({
      where: { token },
      data: { revokedAt: new Date() },
    });
  }

  async deleteUser(username: string) {
    await this.user.update({
      where: { username },
      data: { deleted: true },
    });
  }
}
