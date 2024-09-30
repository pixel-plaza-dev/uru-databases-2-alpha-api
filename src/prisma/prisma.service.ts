import { Injectable, OnModuleInit } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';
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
    email: string,
    select: UserSelectable = {
      id: true,
    },
  ) {
    return this.user.findUnique({
      where: { email },
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
    password,
    firstName,
    lastName,
    address,
    phone,
  }: UserCreate) {
    await this.user.create({
      data: {
        email,
        password,
        firstName,
        lastName,
        address: address ?? Prisma.skip,
        phone: phone ?? Prisma.skip,
      },
    });
  }

  async createRefreshToken({ email, token, expiresAt }: RefreshTokenCreate) {
    await this.user.update({
      where: { email },
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

  async updateAccessTokenLastUsage(id: string) {
    await this.accessToken.update({
      where: { id },
      data: { lastUsedAt: new Date() },
    });
  }

  async invalidateRefreshToken(token: string) {
    await this.refreshToken.updateMany({
      where: { token },
      data: { valid: false },
    });
    await this.accessToken.updateMany({
      where: { refreshToken: { token } },
      data: { valid: false },
    });
  }

  async invalidateRefreshTokens(userId: string) {
    await this.refreshToken.updateMany({
      where: { user: { id: userId } },
      data: { valid: false },
    });
    await this.accessToken.updateMany({
      where: {
        refreshToken: {
          user: { id: userId },
        },
      },
      data: { valid: false },
    });
  }

  async invalidateAccessToken(token: string) {
    await this.accessToken.update({
      where: { token },
      data: { valid: false },
    });
  }
}
