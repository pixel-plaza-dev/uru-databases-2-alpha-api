import { Injectable } from '@nestjs/common';
import { Request, Response } from 'express';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../providers/prisma/prisma.service';
import { UserAuthLoginDto } from '../../dto/user/auth/user-auth-login.dto';
import * as bcrypt from 'bcrypt';
import { UserAuthSignupDto } from '../../dto/user/auth/user-auth-signup.dto';
import { BCRYPT_SALT_ROUNDS, JWT_SECRET } from '../../../config/secrets';
import { BCYPT_ERROR, JWT_TOKEN_EXPIRED_ERROR } from '../../constants/errors';
import { LoggerService } from '../../providers/logger/logger.service';
import { Prisma, Role, UserLoginAttempt, UserRole } from '@prisma/client';
import { awaitConcurrently } from '../../utils/execute-concurrently';
import { JwtRefreshTokenCreate } from '../../providers/prisma/types/jwt-refresh-token-data';
import { JwtAccessTokenCreate } from '../../providers/prisma/types/jwt-access-token';
import { Expiration } from '../../../config/token';
import {
  ACCESS_TOKEN,
  JwtTokenConfig,
  REFRESH_TOKEN,
} from '../../../config/jwt-token';
import { REQUEST_USER, USER_AGENT } from '../../constants/request';
import { PASSWORD_RESET } from '../../../config/password-reset-token';
import { EMAIL_VERIFICATION } from '../../../config/email-verification-token';
import { USER } from '../../constants/user';
import { TOKEN } from '../../constants/token';
import { PRISMA } from '../../constants/prisma';
import { JWT_TOKEN } from '../../constants/jwt-token';
import { EMAIL_VERIFICATION_TOKEN } from '../../constants/email-verification-token';
import { PASSWORD_RESET_TOKEN } from '../../constants/password-reset-token';

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
        this.logger.onUnauthorized(TOKEN.INVALID, err.name);
    }
    return null;
  }

  async signup(user: UserAuthSignupDto) {
    const { username, password, confirmPassword } = user;

    // Get email verification token expiration
    const emailVerificationTokenExpiresAt =
      this.getExpiration(EMAIL_VERIFICATION);

    // Compare passwords
    if (password !== confirmPassword)
      this.logger.onUserBadRequest(USER.PASSWORDS_DO_NOT_MATCH, username);

    // Hash password
    bcrypt.hash(
      user.password,
      BCRYPT_SALT_ROUNDS,
      async (err: any, hash: string) => {
        if (err) this.logger.onInternalServerError(BCYPT_ERROR, err.name);

        try {
          // Create user
          await this.prismaService.createUser(
            { ...user, password: hash },
            { expiresAt: emailVerificationTokenExpiresAt },
          );
        } catch (error) {
          // Check if user exists
          if (error.code === PRISMA.UNIQUE_CONSTRAINT_FAILED)
            this.logger.onUserBadRequest(USER.REGISTERED, username);

          this.logger.onInternalServerError(error.message);
        }
      },
    );

    return this.logger.onUserSuccess(USER.SIGNUP, username);
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
    if (!userFound) this.logger.onUnauthorized(USER.WRONG_CREDENTIALS);

    // Get user agent and IP address
    const userAgent = this.getUserAgentFromRequest(req);
    const ip = this.getIpAddressFromRequest(req);
    const successful = match && !userFound.deleted;

    // Add login attempt
    const userLoginAttempt = await this.prismaService.createUserLoginAttempt(
      username,
      { ip, userAgent, successful },
    );

    // Check if user is not deleted or password is incorrect
    if (!match || userFound.deleted)
      this.logger.onUnauthorized(USER.WRONG_CREDENTIALS);

    try {
      // Create JWT tokens
      await this.createJwtTokensCookiesFromLogin(
        res,
        username,
        userFound.roles,
        userLoginAttempt,
      );
    } catch (error) {
      this.logger.onInternalServerError(error.message);
    }

    return this.logger.onUserSuccess(USER.LOGIN, username);
  }

  async refresh(req: Request, res: Response) {
    // Extract refresh token
    const refreshToken = this.extractTokenFromCookies(req, REFRESH_TOKEN);
    if (!refreshToken) this.logger.onUnauthorized(TOKEN.MISSING);

    // Verify refresh token
    const payload = await this.verifyToken(refreshToken);
    if (payload === null) {
      // Revoke refresh token
      await this.prismaService.revokeJwtRefreshToken(refreshToken);

      this.logger.onUnauthorized(TOKEN.EXPIRED);
    }

    // Get username from payload
    const { username } = payload.data;

    // Get updated roles
    const userRoles = await this.prismaService.findUserRoles(username);

    const tokenFound = await this.prismaService.findJwtRefreshToken(
      refreshToken,
      {
        revokedAt: true,
        usedAt: true,
      },
    );

    // Check if refresh token was found in database
    if (!tokenFound)
      this.logger.onUnauthorized(TOKEN.INVALID, TOKEN.NOT_FOUND_DB);

    // Check if refresh token was revoked
    if (tokenFound.revokedAt !== null)
      this.logger.onUnauthorized(TOKEN.REVOKED);

    // Check if refresh token was used
    if (tokenFound.usedAt !== null)
      this.logger.onUnauthorized(TOKEN.INVALID, TOKEN.USED);

    try {
      // Set refresh token as used and revoke it
      const setRefreshTokenAsUsed =
        this.prismaService.setJwtRefreshTokenAsUsed(refreshToken);

      // Create JWT tokens
      const createJwtTokens = this.createJwtTokensCookiesFromRefresh(
        res,
        username,
        userRoles,
        refreshToken,
      );

      await awaitConcurrently(setRefreshTokenAsUsed, createJwtTokens);
    } catch (error) {
      this.logger.onInternalServerError(error.message);
    }

    return this.logger.onUserSuccess(JWT_TOKEN.REFRESH_SUCCESS, username);
  }

  async createEmailVerificationToken(
    username: string,
    email: string,
  ): Promise<string> {
    // Get expiration date
    const expiresAt = this.getExpiration(EMAIL_VERIFICATION);

    // Add email verification token
    try {
      const emailVerificationToken =
        await this.prismaService.createEmailVerificationToken(
          username,
          email,
          { expiresAt },
          { uuid: true },
        );

      if (!emailVerificationToken)
        this.logger.onUserBadRequest(
          EMAIL_VERIFICATION_TOKEN.FAILED_TO_CREATE,
          username,
        );

      return emailVerificationToken.uuid;
    } catch {
      this.logger.onUserBadRequest(
        EMAIL_VERIFICATION_TOKEN.FAILED_TO_CREATE,
        username,
      );
    }
  }

  async createPasswordResetToken(
    username: string,
    email: string,
  ): Promise<string> {
    // Get expiration date
    const expiresAt = this.getExpiration(PASSWORD_RESET);

    // Add password reset token
    try {
      const passwordResetToken =
        await this.prismaService.createPasswordResetToken(
          username,
          { email, expiresAt },
          { uuid: true },
        );

      if (!passwordResetToken)
        this.logger.onUserBadRequest(
          PASSWORD_RESET_TOKEN.FAILED_TO_CREATE,
          username,
        );

      return passwordResetToken.uuid;
    } catch {
      this.logger.onUserBadRequest(
        PASSWORD_RESET_TOKEN.FAILED_TO_CREATE,
        username,
      );
    }
  }
}
