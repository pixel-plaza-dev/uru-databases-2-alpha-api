import { Body, Controller, Post, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserAuthLoginDto } from '../dto/user/auth/user-auth-login.dto';
import { UserAuthSignupDto } from '../dto/user/auth/user-auth-signup.dto';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  async signup(@Body() user: UserAuthSignupDto) {
    return this.authService.signup(user);
  }

  @Post('login')
  async login(
    @Res({ passthrough: true }) res: Response,
    @Body() user: UserAuthLoginDto,
  ) {
    return this.authService.login(res, user);
  }
}
