import { Controller, Get, UseGuards } from '@nestjs/common';
import { PingService } from './ping.service';
import { Public } from 'src/public/public.decorator';
import { Roles } from '../roles/roles.decorator';
import { Role } from '@prisma/client';
import { AuthGuard } from '../auth/auth.guard';

@UseGuards(AuthGuard)
@Controller('ping')
export class PingController {
  constructor(private readonly pingService: PingService) {}

  @Public()
  @Get('/public')
  ping() {
    return this.pingService.ping();
  }

  @Get('/protected')
  pingProtected() {
    return this.pingService.ping();
  }

  @Get('/protected/admin')
  @Roles(Role.ADMIN)
  pingAdmin() {
    return this.pingService.ping();
  }
}
