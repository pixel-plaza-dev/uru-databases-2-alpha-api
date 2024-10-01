import { Controller, Get, UseGuards } from '@nestjs/common';
import { AuthGuard, Public } from '../auth/auth.guard';
import { PingService } from './ping.service';

@UseGuards(AuthGuard)
@Controller('ping')
export class PingController {
  constructor(private readonly pingService: PingService) {
  }

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
  pingAdmin() {
    return this.pingService.ping();
  }
}
