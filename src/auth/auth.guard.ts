import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthService } from './auth.service';
import { ACCESS_TOKEN } from '../global/config';
import {
  INVALID_TOKEN,
  TOKEN_EXPIRED,
  TOKEN_NOT_FOUND,
} from '../global/errors';
import { LoggerService } from '../logger/logger.service';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new LoggerService(AuthGuard.name);

  constructor(
    private prismaService: PrismaService,
    private authService: AuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
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

    const email = payload.data.email;

    // Check if access token exists
    const tokenFound = await this.prismaService.findAccessToken(accessToken, {
      id: true,
      valid: true,
    });
    if (!tokenFound)
      this.logger.onUnauthorized(INVALID_TOKEN, 'Token not found at database');

    // Check if access token is valid
    if (!tokenFound.valid)
      this.logger.onUnauthorized(INVALID_TOKEN, 'Token is not valid');

    // Update access token last used at date
    await this.prismaService.updateAccessTokenLastUsage(tokenFound.id);

    // Set payload to request object
    req['user'] = { ...payload.data };

    return this.logger.onAuthorized(email);
  }
}
