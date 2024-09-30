import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import {
  AuthService,
  INVALID_TOKEN,
  TOKEN_EXPIRED,
  TOKEN_NOT_FOUND,
} from './auth.service';
import { TokenType } from '@prisma/client';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);

  constructor(
    private prismaService: PrismaService,
    private authService: AuthService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Extract request
    const req = context.switchToHttp().getRequest();

    // Get access token
    const accessToken = this.authService.extractAccessTokenFromCookies(req);

    // Check if access token was found
    if (!accessToken) this.authService.failedToAuthenticate(TOKEN_NOT_FOUND);

    // Verify access token
    const payload = await this.authService.verifyToken(accessToken);
    if (payload === null) throw new UnauthorizedException(TOKEN_EXPIRED);

    const email = payload.data.email;

    // Check if access token exists
    const tokenFound = await this.prismaService.findUserToken(
      accessToken,
      TokenType.ACCESS,
    );
    if (!tokenFound)
      this.authService.failedToAuthenticate(
        INVALID_TOKEN,
        'Token not found at database',
      );

    // Update access token last used at date
    await this.prismaService.updateLastUsedAtToken(tokenFound.id);

    req['user'] = payload;
    this.logger.log('User authenticated: ' + email);
    return true;
  }
}
