import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthService } from './auth.service';
import {
  ACCESS_TOKEN,
  IS_PUBLIC_KEY,
  REQUEST_USER,
  ROLES_KEY,
} from '../global/config';
import {
  INVALID_TOKEN,
  TOKEN_EXPIRED,
  TOKEN_INVALIDATED,
  TOKEN_NOT_FOUND,
  TOKEN_NOT_FOUND_DB,
} from '../global/errors';
import { LoggerService } from '../logger/logger.service';
import { Reflector } from '@nestjs/core';
import { Role } from '@prisma/client';
import { ROLE_AUTH_FAILED } from '../global/messages';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new LoggerService(AuthGuard.name);

  constructor(
    private prismaService: PrismaService,
    private authService: AuthService,
    private reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check if route is public
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) return true;

    // Extract request
    const req = context.switchToHttp().getRequest();

    // Get access token
    const accessToken = this.authService.extractTokenFromCookies(
      req,
      ACCESS_TOKEN,
    );

    // Check if access token was found
    if (!accessToken) this.logger.onUnauthorized(TOKEN_NOT_FOUND);

    // Verify access token
    const payload = await this.authService.verifyToken(accessToken);
    if (payload === null) {
      await this.prismaService.invalidateAccessToken(accessToken);
      this.logger.onUnauthorized(TOKEN_EXPIRED);
    }

    // Check if access token exists
    const tokenFound = await this.prismaService.findAccessToken(accessToken, {
      id: true,
      revokedAt: true,
    });

    // Check if access token was found in database and is valid
    if (!tokenFound || tokenFound.revokedAt !== null)
      this.logger.onUnauthorized(
        INVALID_TOKEN,
        tokenFound ? TOKEN_INVALIDATED : TOKEN_NOT_FOUND_DB,
      );

    // Update access token last used at date
    await this.prismaService.updateAccessTokenLastUsage(tokenFound.id);

    // Set payload to request object
    req[REQUEST_USER] = { ...payload.data };

    // Get username and roles from payload
    const { username, roles } = payload.data;

    // Check if there are required roles
    const requiredRoles = this.reflector.getAllAndOverride<Role[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!requiredRoles) return this.logger.onAuthorized(username, roles);

    // Check if user has some of the required roles
    if (!requiredRoles.some((role) => roles.includes(role)))
      this.logger.onUnauthorized(ROLE_AUTH_FAILED);

    return this.logger.onAuthorizedRole(username, roles);
  }
}
