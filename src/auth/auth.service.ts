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
import convertToMilliseconds from '../../utils/convert-to-ms';
import { IS_PRODUCTION } from '../main';
import { TokenType } from '@prisma/client';

// Hashing
const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// Tokens
export const REFRESH_TOKEN = process.env.REFRESH_TOKEN;
const REFRESH_TOKEN_EXPIRES_IN_STR = process.env.REFRESH_TOKEN_EXPIRES_IN_DAYS;
const REFRESH_TOKEN_EXPIRES_IN = convertToMilliseconds({
  days: parseInt(REFRESH_TOKEN_EXPIRES_IN_STR),
});

export const ACCESS_TOKEN = process.env.ACCESS_TOKEN;
const ACCESS_TOKEN_EXPIRES_IN_STR = process.env.ACCESS_TOKEN_EXPIRES_IN_MINUTES;
const ACCESS_TOKEN_EXPIRES_IN = convertToMilliseconds({
  minutes: parseInt(ACCESS_TOKEN_EXPIRES_IN_STR),
});

// Errors
export const TOKEN_NOT_FOUND =
  'Authorization header not found. Please login again';
export const INVALID_TOKEN = 'Invalid token. Please login again';
export const TOKEN_EXPIRED = 'Please go to "/auth/refresh" to get a new token';

// @nestjs/jwt errors
const JWT_TOKEN_EXPIRED_ERROR = 'TokenExpiredError';

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

  async signToken(email: string, expiresIn: Date) {
    const payload = { email };
    return this.jwtService.signAsync({
      exp: Math.floor(expiresIn.getTime() / 1000),
      data: payload,
    });
  }

  getRefreshTokenExpiration() {
    return new Date(Date.now() + REFRESH_TOKEN_EXPIRES_IN);
  }

  getAccessTokenExpiration() {
    return new Date(Date.now() + ACCESS_TOKEN_EXPIRES_IN);
  }

  setTokenCookie(
    res: Response,
    name: string,
    token: string,
    httpOnly: boolean,
    secure: boolean,
    sameSite: 'strict' | 'lax' | 'none',
    expires: Date,
  ) {
    res.cookie(name, token, {
      httpOnly,
      secure,
      sameSite,
      expires,
    });
  }

  setRefreshTokenCookie(res: Response, token: string, expires: Date) {
    this.setTokenCookie(
      res,
      REFRESH_TOKEN,
      token,
      true,
      IS_PRODUCTION,
      'strict',
      expires,
    );
  }

  setAccessTokenCookie(res: Response, token: string, expires: Date) {
    this.setTokenCookie(
      res,
      ACCESS_TOKEN,
      token,
      true,
      IS_PRODUCTION,
      'strict',
      expires,
    );
  }

  async generateTokens(res: Response, email: string) {
    // Generate tokens
    const refreshTokenExpiration = this.getRefreshTokenExpiration();
    const refreshToken = await this.signToken(email, refreshTokenExpiration);

    const accessTokenExpiration = this.getAccessTokenExpiration();
    const accessToken = await this.signToken(email, accessTokenExpiration);

    // Add tokens to user
    await this.prismaService.createUserToken(
      email,
      refreshToken,
      refreshTokenExpiration,
      TokenType.REFRESH,
    );
    await this.prismaService.createUserToken(
      email,
      accessToken,
      accessTokenExpiration,
      TokenType.ACCESS,
    );

    // Set token cookies
    this.setRefreshTokenCookie(res, refreshToken, refreshTokenExpiration);
    this.setAccessTokenCookie(res, accessToken, accessTokenExpiration);
  }

  extractTokenFromCookies(req: Request, tokenName: string): string | undefined {
    return req.cookies[tokenName];
  }

  extractAccessTokenFromCookies(req: Request): string | undefined {
    return this.extractTokenFromCookies(req, ACCESS_TOKEN);
  }

  extractRefreshTokenFromCookies(req: Request): string | undefined {
    return this.extractTokenFromCookies(req, REFRESH_TOKEN);
  }

  failedToAuthenticate(message: string, errorMessage?: string) {
    this.logger.error('Failed to authenticate: ' + (errorMessage ?? message));
    throw new UnauthorizedException(message);
  }

  async verifyToken(token: string) {
    try {
      return await this.jwtService.verifyAsync(token, {
        secret: JWT_SECRET,
      });
    } catch (err) {
      // Check if token is expired
      if (err._names !== JWT_TOKEN_EXPIRED_ERROR)
        this.failedToAuthenticate(INVALID_TOKEN);
    }
    return null;
  }

  async signup(user: UserAuthSignupDto) {
    // Check if user exists
    const userExists = await this.prismaService.findUser(user.email, {
      id: true,
    });
    if (userExists) {
      this.logger.warn('User email already registered: ' + user.email);
      throw new BadRequestException('User email already registered');
    }

    // Compare passwords
    if (user.password !== user.confirmPassword) {
      this.logger.warn('Passwords do not match: ' + user.email);
      throw new BadRequestException('Passwords do not match`  ');
    }

    // Hash password
    bcrypt.hash(
      user.password,
      BCRYPT_SALT_ROUNDS,
      async (err: any, hash: string) => {
        if (err) {
          this.logger.warn('Error hashing password: ' + err.message);
          throw new InternalServerErrorException('An error occurred!');
        }

        // Create auth
        await this.prismaService.createUser({ ...user, password: hash });
      },
    );

    this.logger.log('User signed up: ' + user.email);
    return {
      statusCode: HttpStatus.CREATED,
      message: 'User signed up',
    };
  }

  async login(res: Response, user: UserAuthLoginDto) {
    const userFound = await this.prismaService.findUser(user.email, {
      password: true,
    });

    const match = userFound
      ? await this.verifyPassword(user.password, userFound.password)
      : false;

    if (!match) {
      this.logger.warn('Wrong email or password: ' + user.email);
      throw new UnauthorizedException('Wrong email or password');
    }

    // Generate tokens
    await this.generateTokens(res, user.email);

    this.logger.log('User logged in: ' + user.email);
    return {
      statusCode: HttpStatus.CREATED,
      message: 'User logged in',
    };
  }

  async refresh(req: Request, res: Response) {
    // Extract refresh token
    const refreshToken = this.extractRefreshTokenFromCookies(req);
    if (!refreshToken) this.failedToAuthenticate(TOKEN_NOT_FOUND);

    // Verify refresh token
    const payload = await this.verifyToken(refreshToken);
    if (!payload) this.failedToAuthenticate(TOKEN_EXPIRED);

    const email = payload.data.email;

    // Check if refresh token exists
    const tokenFound = await this.prismaService.findUserToken(
      refreshToken,
      TokenType.REFRESH,
    );
    if (!tokenFound) this.failedToAuthenticate(INVALID_TOKEN);

    // Generate new tokens
    await this.generateTokens(res, email);

    this.logger.log('Tokens refreshed: ' + email);
    return {
      statusCode: HttpStatus.CREATED,
      message: 'Tokens refreshed',
    };
  }
}
