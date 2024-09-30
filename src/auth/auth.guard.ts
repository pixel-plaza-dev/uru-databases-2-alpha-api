import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { AuthService } from './auth.service';
import { ACCESS_TOKEN } from '../global/config';
import { AUTH_SUCCESS } from '../global/messages';
import {
  INVALID_TOKEN,
  TOKEN_EXPIRED,
  TOKEN_NOT_FOUND,
} from '../global/errors';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);

  constructor(
    private prismaService: PrismaService,
    private authService: AuthService,
  ) {}

  success(req: Request, payload: string, email) {
    req['user'] = payload;
    this.logger.log(`${AUTH_SUCCESS}: ${email}`);
    return true;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Extract request
    const req = context.switchToHttp().getRequest();

    // Get access token
    const accessToken = this.authService.extractTokenFromCookies(
      req,
      ACCESS_TOKEN,
    );

    // Check if access token was found
    if (!accessToken) this.authService.unauthorized(TOKEN_NOT_FOUND);

    // Verify access token
    const payload = await this.authService.verifyToken(accessToken);
    if (payload === null) {
      await this.prismaService.invalidateAccessToken(accessToken);
      this.authService.unauthorized(TOKEN_EXPIRED);
    }

    const email = payload.data.email;

    // Check if access token exists
    const tokenFound = await this.prismaService.findAccessToken(accessToken);
    if (!tokenFound)
      this.authService.unauthorized(
        INVALID_TOKEN,
        'Token not found at database',
      );

    // Update access token last used at date
    await this.prismaService.updateAccessTokenLastUsage(tokenFound.id);

    return this.success(req, payload, email);
  }
}
