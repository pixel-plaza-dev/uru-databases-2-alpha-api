import {
  HttpStatus,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { UserUpdateDto } from '../dto/user/user-update.dto';
import { UserChangeEmailDto } from '../dto/user/user-change-email.dto';
import { UserChangePasswordDto } from '../dto/user/user-change-password.dto';
import { UserForgotPasswordDto } from '../dto/user/user-forgot-password.dto';
import { UserDeleteDto } from '../dto/user/user-delete';
import { UserChangeRoleDto } from '../dto/user/user-change-role.dto';
import { UserCloseAllSessionsDto } from '../dto/user/user-close-all-sessions';
import { Request } from 'express';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class UsersService {
  private readonly logger = new Logger(UsersService.name);

  constructor(
    private prismaService: PrismaService,
    private authService: AuthService,
  ) {}

  async update(user: UserUpdateDto) {
    this.logger.log('User update: ' + user.email);
    return user;
  }

  async changePassword(user: UserChangePasswordDto) {
    this.logger.log('User change password: ' + user.email);
    return user;
  }

  async changeEmail(user: UserChangeEmailDto) {
    this.logger.log('User change email: ' + user.email);
    return user;
  }

  async forgotPassword(user: UserForgotPasswordDto) {
    this.logger.log('User forgot password: ' + user.email);
    return user;
  }

  async logout() {
    this.logger.log('User logout');
    return 'User logout';
  }

  async closeAllSessions(req: Request, user: UserCloseAllSessionsDto) {
    const email = req['user'].email;
    this.logger.log('User logout all: ' + email);

    // Verify password
    const userFound = await this.prismaService.findUser(email, {
      password: true,
      id: true,
    });
    const match = await this.authService.verifyPassword(
      user.password,
      userFound.password,
    );

    if (!match) {
      this.logger.warn('Invalid password: ' + email);
      throw new UnauthorizedException();
    }

    // Delete all tokens
    await this.prismaService.deleteUserTokens(userFound.id);

    this.logger.log('All sessions closed: ' + email);
    return {
      statusCode: HttpStatus.OK,
      message: 'All sessions closed',
    };
  }

  async delete(user: UserDeleteDto) {
    this.logger.log('User delete: ' + user.email);
    return user;
  }

  async changeRole(user: UserChangeRoleDto) {
    this.logger.log('User change role: ' + user.email);
    return user;
  }
}
