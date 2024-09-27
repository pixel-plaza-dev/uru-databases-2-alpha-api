import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Welcome to Alpha API! Checkout the documentation at /docs';
  }
}
