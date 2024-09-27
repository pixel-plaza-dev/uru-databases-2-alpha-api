import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { PrismaService } from '../prisma/prisma.service';

const JWT_SECRET = process.env.JWT_SECRET;

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);

  constructor(
    private jwtService: JwtService,
    private prismaService: PrismaService,
  ) {}

  failedToAuthenticate(message: string) {
    this.logger.error('Failed to authenticate: ' + message);
    throw new UnauthorizedException();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    let payload: any;

    if (!token) this.failedToAuthenticate('No token provided');

    try {
      payload = await this.jwtService.verifyAsync(token, {
        secret: JWT_SECRET,
      });
    } catch {
      this.failedToAuthenticate('Invalid token');
    }
    // Check if token exists
    const tokenFound = await this.prismaService.token.findUnique({
      where: { token: token },
    });
    if (!tokenFound) this.failedToAuthenticate('Token not found');

    // Check if token date is expired
    //if (tokenExists.createdAt<payload.) throw new UnauthorizedException();

    // Update token last used date
    await this.prismaService.updateToken(tokenFound.id);

    request['user'] = payload;
    this.logger.log('User authenticated: ' + payload.email);
    return true;
  }

  private extractTokenFromHeader(req: Request): string | undefined {
    return req.cookies.access_token;
  }
}
