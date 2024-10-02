import { Injectable, OnModuleInit } from '@nestjs/common';
import { Prisma, PrismaClient, Role } from '@prisma/client';
import { UserCreate, UserSelectable } from './interfaces/user';
import {
  RefreshTokenCreate,
  RefreshTokenSelectable,
} from './interfaces/refresh-token';
import {
  AccessTokenCreate,
  AccessTokenSelectable,
} from './interfaces/access-token';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  async onModuleInit() {
    await this.$connect();
  }

  async findUser(
    username: string,
    select: UserSelectable = {
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
    select: RefreshTokenSelectable = { id: true },
  ) {
    return this.refreshToken.findUnique({
      where: { token },
      select,
    });
  }

  async findAccessToken(
    token: string,
    select: AccessTokenSelectable = { id: true },
  ) {
    return this.accessToken.findUnique({
      where: { token },
      select,
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
  }: UserCreate) {
    await this.user.create({
      data: {
        email,
        username,
        password,
        firstName,
        lastName,
        address: address ?? Prisma.skip,
        phone: phone ?? Prisma.skip,
        roles: { create: { role: Role.USER } },
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

  async deleteUser(username: string) {
    await this.user.update({
      where: { username },
      data: { deleted: true },
    });
  }

  async updateAccessTokenLastUsage(id: string) {
    await this.accessToken.update({
      where: { id },
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
}
