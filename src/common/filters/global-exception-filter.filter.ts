import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
} from '@nestjs/common';
import { HttpAdapterHost } from '@nestjs/core';
import { INTERNAL_SERVER_ERROR } from '../constants/errors';
import { LoggerService } from '../providers/logger/logger.service';

@Catch()
export class GlobalExceptionFilter implements ExceptionFilter {
  private readonly logger = new LoggerService(GlobalExceptionFilter.name);

  constructor(private readonly httpAdapterHost: HttpAdapterHost) {}

  catch(exception: unknown, host: ArgumentsHost) {
    // In certain situations `httpAdapter` might not be available in the
    // constructor method, thus we should resolve it here.
    const { httpAdapter } = this.httpAdapterHost;

    const ctx = host.switchToHttp();

    // Get the status code from the exception
    const httpStatus =
      exception instanceof HttpException
        ? exception.getStatus()
        : HttpStatus.INTERNAL_SERVER_ERROR;

    // Get the exception message
    let message: string;

    if (!(exception instanceof HttpException)) {
      message = exception['message'] || INTERNAL_SERVER_ERROR;

      // Log the unhandled exception
      this.logger.onUnhandledError(exception);
    } else if (httpStatus === HttpStatus.INTERNAL_SERVER_ERROR)
      message = INTERNAL_SERVER_ERROR;
    else message = exception.getResponse()['message'] || INTERNAL_SERVER_ERROR;

    const responseBody = {
      statusCode: httpStatus,
      message,
    };

    httpAdapter.reply(ctx.getResponse(), responseBody, httpStatus);
  }
}
