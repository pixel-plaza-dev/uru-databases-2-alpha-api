import { Injectable, OnModuleInit } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit {
  async onModuleInit() {
    await this.$connect();
  }

  async createUser({
    email,
    password,
    firstName,
    lastName,
    address,
    phone,
  }: {
    email: string;
    password: string;
    firstName: string;
    lastName: string;
    address?: string;
    phone?: string;
  }) {
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

  async findUser(
    email: string,
    select: {
      id?: boolean;
      password?: boolean;
      name?: boolean;
      address?: boolean;
      phone?: boolean;
      email?: true;
    } = {
      email: true,
      id: true,
      password: true,
      name: true,
      address: true,
      phone: true,
    },
  ) {
    return this.user.findUnique({
      where: { email },
      select,
    });
  }

  async findRefreshToken(token: string) {
    return this.refreshToken.findUnique({
      where: { token },
    });
  }

  async findAccessToken(token: string) {
    return this.accessToken.findUnique({
      where: { token },
    });
  }

  async createRefreshToken(email: string, token: string, expiresAt: Date) {
    await this.user.update({
      where: { email },
      data: { refreshTokens: { create: { token, expiresAt } } },
    });
  }

  async createAccessToken(
    token: string,
    expiresAt: Date,
    refreshToken: string,
  ) {
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

  async invalidateAccessToken(token: string) {
    await this.accessToken.update({
      where: { token },
      data: { valid: false },
    });
  }

  async invalidateRefreshToken(token: string) {
      await this.refreshToken.updateMany({
        where: { token },
        data: { valid: false },
      })
      await this.accessToken.updateMany({
        where: { refreshToken: { token } },
        data: { valid: false },
      });
  }
}
