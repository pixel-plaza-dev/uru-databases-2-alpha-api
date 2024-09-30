import { Injectable, OnModuleInit } from '@nestjs/common';
import { Prisma, PrismaClient, TokenType } from '@prisma/client';

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
    return this.user.create({
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

  async findUserToken(token: string, tokenType: TokenType) {
    return this.token.findUnique({
      where: { token, tokenType },
    });
  }

  async createUserToken(
    email: string,
    token: string,
    expiresAt: Date,
    tokenType: TokenType,
  ) {
    return this.user.update({
      where: { email },
      data: { tokens: { create: { token, expiresAt, tokenType } } },
    });
  }

  async deleteUserTokens(userId: string) {
    return this.token.deleteMany({
      where: { userId },
    });
  }

  async updateLastUsedAtToken(id: string) {
    return this.token.update({
      where: { id },
      data: { lastUsedAt: new Date() },
    });
  }
}
