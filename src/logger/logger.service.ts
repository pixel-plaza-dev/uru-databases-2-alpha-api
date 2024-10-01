import {
  BadRequestException,
  HttpStatus,
  Injectable,
  InternalServerErrorException,
  Logger,
  Scope,
  UnauthorizedException,
} from '@nestjs/common';
import { AUTH_FAILED, AUTH_SUCCESS } from '../global/messages';
import { INTERNAL_SERVER_ERROR } from '../global/errors';

@Injectable({ scope: Scope.TRANSIENT })
export class LoggerService extends Logger {
  onUnauthorized(message: string, errorMessage?: string) {
    super.warn(`${AUTH_FAILED}: ${message ?? errorMessage}`);
    throw new UnauthorizedException(message);
  }

  onAuthorized(username: string) {
    super.log(`${AUTH_SUCCESS}: ${username}`);
    return true;
  }

  onUserBadRequest(message: string, username: string) {
    super.warn(`${message}: ${username}`);
    throw new BadRequestException(message);
  }

  onInternalServerError(message: string, errorMessage: string) {
    super.error(`${message}: ${errorMessage}`);
    throw new InternalServerErrorException(INTERNAL_SERVER_ERROR);
  }

  onPingSuccess(message: string) {
    super.log(message);
    return {
      statusCode: HttpStatus.OK,
      message,
    };
  }

  onUserSuccess(
    message: string,
    username: string,
    statusCode: HttpStatus = HttpStatus.CREATED,
  ) {
    super.log(`${message}: ${username}`);
    return {
      statusCode,
      message: message,
    };
  }
}
