import { Injectable } from '@nestjs/common';
import { LoggerService } from '../common/providers/logger/logger.service';

@Injectable()
export class PingService {
  private readonly logger = new LoggerService(PingService.name);

  constructor() {}

  ping() {
    return this.logger.onPingSuccess();
  }
}
