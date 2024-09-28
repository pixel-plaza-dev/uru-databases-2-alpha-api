import {
  BadRequestException,
  HttpStatus,
  Injectable,
  InternalServerErrorException,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Response } from 'express';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../prisma/prisma.service';
import { UserAuthLoginDto } from '../dto/user/auth/user-auth-login.dto';
import * as bcrypt from 'bcrypt';
import { UserAuthSignupDto } from '../dto/user/auth/user-auth-signup.dto';

const BCRYPT_SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12;

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signToken(email: string) {
    const payload = { email };
    return this.jwtService.signAsync(payload);
  }

  async verifyPassword(password: string, hash: string) {
    return await bcrypt.compare(password, hash);
  }

  setAccessTokenCookie(res: Response, token: string) {
    res.cookie('access_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    });
  }

  async signup(user: UserAuthSignupDto) {
    // Check if auth exists
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

    // Sign user token
    const token = await this.signToken(user.email);

    // Add token to user
    await this.prismaService.createUserToken(user.email, token);

    // Set access token cookie
    this.setAccessTokenCookie(res, token);

    this.logger.log('User logged in: ' + user.email);
    return {
      statusCode: HttpStatus.CREATED,
      message: 'User logged in',
    };
  }
}
