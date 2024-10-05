import { Injectable } from '@nestjs/common';
import { Request, Response } from 'express';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../prisma/prisma.service';
import { UserAuthLoginDto } from '../../dto/user/auth/user-auth-login.dto';
import * as bcrypt from 'bcrypt';
import { UserAuthSignupDto } from '../../dto/user/auth/user-auth-signup.dto';
import {
  ACCESS_TOKEN,
  BCRYPT_SALT_ROUNDS,
  EMAIL_VERIFICATION,
  Expiration,
  JWT_SECRET,
  JwtTokenConfig,
  PASSWORD_RESET,
  REFRESH_TOKEN,
  REQUEST_USER,
  USER_AGENT,
} from '../../global/config';
import {
  TOKEN_REFRESH_SUCCESS,
  USER_LOGIN,
  USER_SIGNUP,
} from '../../global/messages';
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
} from '../../global/errors';
import { LoggerService } from '../../logger/logger.service';
import { Prisma, Role, UserLoginAttempt, UserRole } from '@prisma/client';
import { awaitConcurrently } from '../../utils/execute-concurrently';
import { JwtRefreshTokenCreate } from '../../prisma/types/jwt-refresh-token-data';
import { JwtAccessTokenCreate } from '../../prisma/types/jwt-access-token';

export interface JwtPayload {
  data: JwtPayloadData;
}

export interface JwtPayloadData {
  username: string;
  roles: Role[];
}

@Injectable()
export class AuthService {
  private readonly logger = new LoggerService(AuthService.name);

  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async bcryptComparePasswords(
    password: string,
    hash: string,
  ): Promise<{ userFound: string; match: boolean }> {
    return await bcrypt.compare(password, hash);
  }

  async verifyUserPassword(
    username: string,
    password: string,
    select?: Prisma.UserSelect,
  ) {
    // Get user password
    const userFound = await this.prismaService.findUser(username, {
      ...select,
      password: true,
    });

    // Compare passwords
    const match = !userFound
      ? false
      : await this.bcryptComparePasswords(password, userFound.password);

    return { userFound, match };
  }

  async signToken(data: JwtPayloadData, expiresIn: Date) {
    return this.jwtService.signAsync({
      exp: Math.floor(expiresIn.getTime() / 1000),
      data,
    });
  }

  getExpiration(expiration: Expiration): Date {
    return new Date(Date.now() + expiration.expiresIn);
  }

  setTokenCookie(
    res: Response,
    token: string,
    tokenType: JwtTokenConfig,
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

  extractRoles(userRoles: UserRole[]): Role[] {
    return userRoles.map((userRole) => userRole.role);
  }

  async createJwtTokens(
    username: string,
    userRoles: UserRole[],
  ): Promise<{
    jwtRefreshToken: JwtRefreshTokenCreate;
    jwtAccessToken: JwtAccessTokenCreate;
  }> {
    // Get expiration dates
    const refreshExpiresAt = this.getExpiration(REFRESH_TOKEN);
    const accessExpiresAt = this.getExpiration(ACCESS_TOKEN);

    // Extract roles
    const roles = this.extractRoles(userRoles);

    // Create JWT tokens
    const refreshToken = await this.signToken(
      { username, roles },
      refreshExpiresAt,
    );
    const accessToken = await this.signToken(
      { username, roles },
      accessExpiresAt,
    );

    return {
      jwtRefreshToken: { token: refreshToken, expiresAt: refreshExpiresAt },
      jwtAccessToken: { token: accessToken, expiresAt: accessExpiresAt },
    };
  }

  async setTokenCookies(
    res: Response,
    { token: refreshToken, expiresAt: refreshExpiresAt }: JwtRefreshTokenCreate,
    { token: accessToken, expiresAt: accessExpiresAt }: JwtAccessTokenCreate,
  ): Promise<void> {
    // Set refresh token cookie
    this.setTokenCookie(res, refreshToken, REFRESH_TOKEN, refreshExpiresAt);

    // Set access token cookie
    this.setTokenCookie(res, accessToken, ACCESS_TOKEN, accessExpiresAt);
  }

  async createJwtTokensCookiesFromLogin(
    res: Response,
    username: string,
    userRoles: UserRole[],
    userLoginAttempt: UserLoginAttempt,
  ): Promise<void> {
    // Create JWT tokens
    const { jwtRefreshToken, jwtAccessToken } = await this.createJwtTokens(
      username,
      userRoles,
    );

    // Add token to user
    await this.prismaService.createJwtRefreshTokenFromLogin(
      username,
      userLoginAttempt,
      jwtRefreshToken,
      jwtAccessToken,
    );

    // Set refresh and access tokens as cookies
    await this.setTokenCookies(res, jwtRefreshToken, jwtAccessToken);
  }

  async createJwtTokensCookiesFromRefresh(
    res: Response,
    username: string,
    userRoles: UserRole[],
    parentJwtRefreshToken: string,
  ): Promise<void> {
    // Create JWT tokens
    const { jwtRefreshToken, jwtAccessToken } = await this.createJwtTokens(
      username,
      userRoles,
    );

    // Add token to user
    await this.prismaService.createJwtRefreshTokenFromRefresh(
      username,
      parentJwtRefreshToken,
      jwtRefreshToken,
      jwtAccessToken,
    );

    // Set refresh and access tokens as cookies
    await this.setTokenCookies(res, jwtRefreshToken, jwtAccessToken);
  }

  extractTokenFromCookies(
    req: Request,
    config: JwtTokenConfig,
  ): string | undefined {
    return req.cookies[config.name];
  }

  getJwtDataFromRequest(req: Request): JwtPayloadData {
    return req[REQUEST_USER];
  }

  getIpAddressFromRequest(req: Request): string {
    return req.ip;
  }

  getUserAgentFromRequest(req: Request): string {
    return req.headers[USER_AGENT] as string;
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

    // Get email verification token expiration
    const emailVerificationTokenExpiresAt =
      this.getExpiration(EMAIL_VERIFICATION);

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
        await this.prismaService.createUser(
          { ...user, password: hash },
          { expiresAt: emailVerificationTokenExpiresAt },
        );
      },
    );

    return this.logger.onUserSuccess(USER_SIGNUP, username);
  }

  async login(req: Request, res: Response, user: UserAuthLoginDto) {
    const { username, password } = user;

    // Verify user password
    const { userFound, match } = await this.verifyUserPassword(
      username,
      password,
      { deleted: true, roles: true },
    );

    // Check if user exists
    if (!userFound) this.logger.onUnauthorized(USER_WRONG_CREDENTIALS);

    // Get user agent and IP address
    const userAgent = this.getUserAgentFromRequest(req);
    const ip = this.getIpAddressFromRequest(req);
    const successful = !userFound.deleted;

    // Add login attempt
    const userLoginAttempt = await this.prismaService.createUserLoginAttempt(
      username,
      { ip, userAgent, successful },
    );

    // Check if user is not deleted or password is incorrect
    if (!match || userFound.deleted)
      this.logger.onUnauthorized(USER_WRONG_CREDENTIALS);

    // Create JWT tokens
    await this.createJwtTokensCookiesFromLogin(
      res,
      username,
      userFound.roles,
      userLoginAttempt,
    );

    return this.logger.onUserSuccess(USER_LOGIN, username);
  }

  async refresh(req: Request, res: Response) {
    // Extract refresh token
    const refreshToken = this.extractTokenFromCookies(req, REFRESH_TOKEN);
    if (!refreshToken) this.logger.onUnauthorized(TOKEN_NOT_FOUND);

    // Verify refresh token
    const payload = await this.verifyToken(refreshToken);
    if (payload === null) {
      // Revoke refresh token
      await this.prismaService.revokeRefreshToken(refreshToken);

      this.logger.onUnauthorized(TOKEN_EXPIRED);
    }

    // Get username from payload
    const { username } = payload.data;

    // Get updated roles
    const userRoles = await this.prismaService.findUserRoles(username);

    // Check if refresh token was found in database and is valid
    const tokenFound = await this.prismaService.findJwtRefreshToken(
      refreshToken,
      {
        revokedAt: true,
      },
    );
    if (!tokenFound || tokenFound.revokedAt !== null)
      this.logger.onUnauthorized(
        INVALID_TOKEN,
        tokenFound ? TOKEN_INVALIDATED : TOKEN_NOT_FOUND_DB,
      );

    // Set refresh token as used
    const setRefreshTokenAsUsed =
      this.prismaService.setRefreshTokenAsUsed(refreshToken);

    // Revoke refresh token
    const revokeRefreshToken =
      this.prismaService.revokeRefreshToken(refreshToken);

    // Create JWT tokens
    const createJwtTokens = this.createJwtTokensCookiesFromRefresh(
      res,
      username,
      userRoles,
      refreshToken,
    );

    await awaitConcurrently(
      setRefreshTokenAsUsed,
      revokeRefreshToken,
      createJwtTokens,
    );

    return this.logger.onUserSuccess(TOKEN_REFRESH_SUCCESS, username);
  }

  async createEmailVerificationToken(
    username: string,
    email: string,
  ): Promise<string> {
    // Get expiration date
    const expiresAt = this.getExpiration(EMAIL_VERIFICATION);

    // Add email verification token
    const emailVerificationToken =
      await this.prismaService.createEmailVerificationToken(username, {
        email,
        expiresAt,
      });

    return emailVerificationToken.uuid;
  }

  async createPasswordResetToken(
    username: string,
    email: string,
  ): Promise<string> {
    // Get expiration date
    const expiresAt = this.getExpiration(PASSWORD_RESET);

    // Add password reset token
    const passwordResetToken =
      await this.prismaService.createPasswordResetToken(username, {
        email,
        expiresAt,
      });

    return passwordResetToken.uuid;
  }
}
