import { Injectable } from '@nestjs/common';
import { LoggerService } from '../logger/logger.service';
import { PONG } from '../global/messages';

@Injectable()
export class PingService {
  private readonly logger = new LoggerService(PingService.name);

  constructor() {}

  ping() {
    return this.logger.onPingSuccess(PONG);
  }
}
