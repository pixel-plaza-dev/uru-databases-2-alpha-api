import { Injectable } from '@nestjs/common';
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
  TOKEN_REFRESH_SUCCESS,
  USER_LOGIN,
  USER_SIGNUP,
} from '../global/messages';
import {
  BCYPT_ERROR,
  INVALID_TOKEN,
  JWT_TOKEN_EXPIRED_ERROR,
  TOKEN_EXPIRED,
  TOKEN_INVALIDATED,
  TOKEN_NOT_FOUND,
  TOKEN_NOT_FOUND_DB,
  USER_PASSWORDS_DO_NOT_MATCH,
  USER_REGISTERED,
  USER_WRONG_CREDENTIALS,
} from '../global/errors';
import { LoggerService } from '../logger/logger.service';
import { UserSelectable } from '../prisma/interfaces/user';

@Injectable()
export class AuthService {
  private readonly logger = new LoggerService(AuthService.name);

  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async comparePasswords(password: string, hash: string): Promise<boolean> {
    return await bcrypt.compare(password, hash);
  }

  async verifyUserPassword(
    username: string,
    password: string,
    select?: UserSelectable,
  ) {
    // Get user password
    const userFound = await this.prismaService.findUser(username, {
      ...select,
      password: true,
    });

    // Compare passwords
    const match = !userFound
      ? false
      : await this.comparePasswords(password, userFound.password);

    if (!match) this.logger.onUnauthorized(USER_WRONG_CREDENTIALS);

    return userFound;
  }

  async signToken(data: object, expiresIn: Date) {
    return this.jwtService.signAsync({
      exp: Math.floor(expiresIn.getTime() / 1000),
      data,
    });
  }

  getTokenExpiration(tokenType: AuthTokenConfig): Date {
    return new Date(Date.now() + tokenType.expiresIn);
  }

  setTokenCookie(
    res: Response,
    token: string,
    tokenType: AuthTokenConfig,
    expires: Date,
  ): void {
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
    username: string,
    config: AuthTokenConfig,
    refreshToken?: string,
  ): Promise<string> {
    // Generate token
    const tokenExpiresAt = this.getTokenExpiration(config);
    const payload = refreshToken ? { username, refreshToken } : { username };
    const token = await this.signToken(payload, tokenExpiresAt);

    // Add token to user
    if (!refreshToken)
      await this.prismaService.createRefreshToken({
        username,
        token,
        expiresAt: tokenExpiresAt,
      });
    else
      await this.prismaService.createAccessToken({
        token,
        expiresAt: tokenExpiresAt,
        refreshToken,
      });

    // Set token cookie
    this.setTokenCookie(res, token, config, tokenExpiresAt);

    return token;
  }

  async generateTokens(res: Response, username: string): Promise<void> {
    // Generate refresh and access token
    const refreshToken = await this.generateToken(res, username, REFRESH_TOKEN);
    await this.generateToken(res, username, ACCESS_TOKEN, refreshToken);
  }

  extractTokenFromCookies(
    req: Request,
    config: AuthTokenConfig,
  ): string | undefined {
    return req.cookies[config.name];
  }

  getUsernameFromPayload(payload: any) {
    return payload.data.username;
  }

  getUsernameFromData(data: any) {
    return data.username;
  }

  async verifyToken(token: string) {
    try {
      return await this.jwtService.verifyAsync(token, {
        secret: JWT_SECRET,
      });
    } catch (err) {
      // Check if token is expired
      if (err.name !== JWT_TOKEN_EXPIRED_ERROR)
        this.logger.onUnauthorized(INVALID_TOKEN, err.name);
    }
    return null;
  }

  async signup(user: UserAuthSignupDto) {
    const { username, password, confirmPassword } = user;

    // Check if user exists
    const userExists = await this.prismaService.findUser(username);
    if (userExists) this.logger.onUserBadRequest(USER_REGISTERED, username);

    // Compare passwords
    if (password !== confirmPassword)
      this.logger.onUserBadRequest(USER_PASSWORDS_DO_NOT_MATCH, username);

    // Hash password
    bcrypt.hash(
      user.password,
      BCRYPT_SALT_ROUNDS,
      async (err: any, hash: string) => {
        if (err) this.logger.onInternalServerError(BCYPT_ERROR, err.name);

        // Create user
        await this.prismaService.createUser({ ...user, password: hash });
      },
    );

    return this.logger.onUserSuccess(USER_SIGNUP, username);
  }

  async login(res: Response, user: UserAuthLoginDto) {
    const { username, password } = user;

    // Verify user password
    const userFound = await this.verifyUserPassword(username, password, {
      deleted: true, role: true,
    });

    // Check if user exists and is not deleted
    if (!userFound || userFound.deleted)
      this.logger.onUnauthorized(USER_WRONG_CREDENTIALS);

    // Generate tokens
    await this.generateTokens(res, username);

    return this.logger.onUserSuccess(USER_LOGIN, username);
  }

  async refresh(req: Request, res: Response) {
    // Extract refresh token
    const refreshToken = this.extractTokenFromCookies(req, REFRESH_TOKEN);
    if (!refreshToken) this.logger.onUnauthorized(TOKEN_NOT_FOUND);

    // Verify refresh token
    const payload = await this.verifyToken(refreshToken);
    if (payload === null) {
      await this.prismaService.invalidateRefreshToken(refreshToken);
      this.logger.onUnauthorized(TOKEN_EXPIRED);
    }

    const username = this.getUsernameFromPayload(payload);

    // Check if refresh token was found in database and is valid
    const tokenFound = await this.prismaService.findRefreshToken(refreshToken);
    if (!tokenFound || !tokenFound.valid)
      this.logger.onUnauthorized(
        INVALID_TOKEN,
        tokenFound ? TOKEN_INVALIDATED : TOKEN_NOT_FOUND_DB,
      );

    await (() => {
      // Invalidate refresh token
      const p1 = this.prismaService.invalidateRefreshToken(refreshToken);

      // Generate new tokens
      const p2 = this.generateTokens(res, username);

      return Promise.all([p1, p2]);
    })();

    return this.logger.onUserSuccess(TOKEN_REFRESH_SUCCESS, username);
  }
}
