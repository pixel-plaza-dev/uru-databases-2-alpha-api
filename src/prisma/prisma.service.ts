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
    name,
    address,
    phone,
  }: {
    email: string;
    password: string;
    name: string;
    address?: string;
    phone?: string;
  }) {
    return this.user.create({
      data: {
        email,
        password,
        name,
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

  async createUserToken(email: string, token: string) {
    return this.user.update({
      where: { email },
      data: { tokens: { create: { token } } },
    });
  }

  async deleteUserTokens(userId: string) {
    return this.token.deleteMany({
      where: { userId },
    });
  }

  async updateToken(id: string) {
    return this.token.update({
      where: { id },
      data: { lastUsedAt: new Date() },
    });
  }
}
