import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { PrismaService } from '../../providers/prisma/prisma.service';
import { AuthService } from './auth.service';
import { LoggerService } from '../../providers/logger/logger.service';
import { Reflector } from '@nestjs/core';
import { Role } from '@prisma/client';
import { ACCESS_TOKEN } from '../../../config/jwt-token';
import { REQUEST_USER } from '../../constants/request';
import { IS_PUBLIC_KEY, ROLES_KEY } from '../../constants/decorators';
import { TOKEN } from '../../constants/token';

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
    if (!accessToken) this.logger.onUnauthorized(TOKEN.MISSING);

    // Verify access token
    const payload = await this.authService.verifyToken(accessToken);

    // Check if access token is expired
    if (payload === null) {
      // Revoke access token
      await this.prismaService.revokeJwtAccessToken(accessToken);

      this.logger.onUnauthorized(TOKEN.EXPIRED);
    }

    const tokenFound = await this.prismaService.findJwtAccessToken(
      accessToken,
      {
        revokedAt: true,
      },
    );

    // Check if access token was found in database
    if (!tokenFound)
      this.logger.onUnauthorized(TOKEN.INVALID, TOKEN.NOT_FOUND_DB);

    // Check if access token is not revoked
    if (tokenFound.revokedAt !== null)
      this.logger.onUnauthorized(TOKEN.REVOKED);

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
      this.logger.onUnauthorizedRole(username, roles);

    return this.logger.onAuthorizedRole(username, roles);
  }
}
