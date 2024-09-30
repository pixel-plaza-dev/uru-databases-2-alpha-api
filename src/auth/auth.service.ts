import {
  BadRequestException,
  HttpStatus,
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Request, Response } from 'express';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { UserAuthLoginDto } from '../dto/user/auth/user-auth-login.dto';
import * as bcrypt from 'bcrypt';
import { UserAuthSignupDto } from '../dto/user/auth/user-auth-signup.dto';
import {
  ACCESS_TOKEN,
  AuthTokenConfig,
  BCRYPT_SALT_ROUNDS,
  JWT_SECRET,
  REFRESH_TOKEN,
} from '../global/config';
import {
  AUTH_FAILED,
  TOKEN_REFRESH_SUCCESS,
  USER_LOGIN_SUCCESS,
  USER_SIGNUP_SUCCESS,
} from '../global/messages';
import {
  BCYPT_ERROR,
  INTERNAL_SERVER_ERROR,
  INVALID_TOKEN,
  JWT_TOKEN_EXPIRED_ERROR,
  TOKEN_EXPIRED,
  TOKEN_NOT_FOUND,
  USER_PASSWORDS_DO_NOT_MATCH,
  USER_REGISTERED,
  USER_WRONG_CREDENTIALS,
} from '../global/errors';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async verifyPassword(password: string, hash: string) {
    return await bcrypt.compare(password, hash);
  }

  async signToken(data: object, expiresIn: Date) {
    return this.jwtService.signAsync({
      exp: Math.floor(expiresIn.getTime() / 1000),
      data,
    });
  }

  getTokenExpiration(tokenType: AuthTokenConfig) {
    return new Date(Date.now() + tokenType.expiresIn);
  }

  setTokenCookie(
    res: Response,
    token: string,
    tokenType: AuthTokenConfig,
    expires: Date,
  ) {
    const { httpOnly, secure, sameSite } = tokenType.options;
    res.cookie(tokenType.name, token, {
      httpOnly,
      secure,
      sameSite,
      expires,
    });
  }

  async generateToken(
    res: Response,
    email: string,
    config: AuthTokenConfig,
    refreshToken?: string,
  ) {
    // Generate token
    const tokenExpiresAt = this.getTokenExpiration(config);
    const payload = refreshToken ? { email, refreshToken } : { email };
    const token = await this.signToken(payload, tokenExpiresAt);

    // Add token to user
    if (!refreshToken)
      await this.prismaService.createRefreshToken(email, token, tokenExpiresAt);
    else
      await this.prismaService.createAccessToken(
        token,
        tokenExpiresAt,
        refreshToken,
      );

    // Set token cookie
    this.setTokenCookie(res, token, config, tokenExpiresAt);

    return token;
  }

  async generateTokens(res: Response, email: string) {
    // Generate refresh and access token
    const refreshToken = await this.generateToken(res, email, REFRESH_TOKEN);
    await this.generateToken(res, email, ACCESS_TOKEN, refreshToken);
  }

  extractTokenFromCookies(
    req: Request,
    config: AuthTokenConfig,
  ): string | undefined {
    return req.cookies[config.name];
  }

  badRequest(message: string, email: string) {
    this.logger.warn(`${message}: ${email}`);
    throw new BadRequestException(message);
  }

  internalServerError(message: string, errorMessage: string) {
    this.logger.error(`${message}: ${errorMessage}`);
    throw new InternalServerErrorException(INTERNAL_SERVER_ERROR);
  }

  unauthorized(message: string, errorMessage?: string) {
    this.logger.warn(`${AUTH_FAILED}: ${message ?? errorMessage}`);
    throw new UnauthorizedException(message);
  }

  success(
    message: string,
    email: string,
    statusCode: HttpStatus = HttpStatus.CREATED,
  ) {
    this.logger.log(`${message}: ${email}`);
    return {
      statusCode,
      message: message,
    };
  }

  async verifyToken(token: string) {
    try {
      return await this.jwtService.verifyAsync(token, {
        secret: JWT_SECRET,
      });
    } catch (err) {
      // Check if token is expired
      if (err.name !== JWT_TOKEN_EXPIRED_ERROR)
        this.unauthorized(INVALID_TOKEN, err.name);
    }
    return null;
  }

  async signup(user: UserAuthSignupDto) {
    // Check if user exists
    const userExists = await this.prismaService.findUser(user.email, {
      id: true,
    });
    if (userExists) this.badRequest(USER_REGISTERED, user.email);

    // Compare passwords
    if (user.password !== user.confirmPassword)
      this.badRequest(USER_PASSWORDS_DO_NOT_MATCH, user.email);

    // Hash password
    bcrypt.hash(
      user.password,
      BCRYPT_SALT_ROUNDS,
      async (err: any, hash: string) => {
        if (err) this.internalServerError(BCYPT_ERROR, err.name);

        // Create user
        await this.prismaService.createUser({ ...user, password: hash });
      },
    );

    return this.success(USER_SIGNUP_SUCCESS, user.email);
  }

  async login(res: Response, user: UserAuthLoginDto) {
    const userFound = await this.prismaService.findUser(user.email, {
      password: true,
    });

    const match = userFound
      ? await this.verifyPassword(user.password, userFound.password)
      : false;

    if (!match) this.unauthorized(USER_WRONG_CREDENTIALS);

    // Generate tokens
    await this.generateTokens(res, user.email);

    return this.success(USER_LOGIN_SUCCESS, user.email);
  }

  async refresh(req: Request, res: Response) {
    // Extract refresh token
    const refreshToken = this.extractTokenFromCookies(req, REFRESH_TOKEN);
    if (!refreshToken) this.unauthorized(TOKEN_NOT_FOUND);

    // Verify refresh token
    const payload = await this.verifyToken(refreshToken);
    if (payload === null) {
      await this.prismaService.invalidateRefreshToken(refreshToken);
      this.unauthorized(TOKEN_EXPIRED);
    }

    const email = payload.data.email;

    // Check if refresh token exists
    const tokenFound = await this.prismaService.findRefreshToken(refreshToken);
    if (!tokenFound) this.unauthorized(INVALID_TOKEN);

    // Invalidate refresh token
    await this.prismaService.invalidateRefreshToken(refreshToken);

    // Generate new tokens
    await this.generateTokens(res, email);

    return this.success(TOKEN_REFRESH_SUCCESS, email);
  }
}
