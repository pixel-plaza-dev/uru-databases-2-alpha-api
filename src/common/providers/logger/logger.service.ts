import {
  BadRequestException,
  HttpStatus,
  Injectable,
  InternalServerErrorException,
  Logger,
  Scope,
  UnauthorizedException,
} from '@nestjs/common';
import { PONG } from '../../constants/messages';
import { INTERNAL_SERVER_ERROR } from '../../constants/errors';
import { Role, UserRoleAction } from '@prisma/client';
import { AUTH } from '../../constants/auth';
import { USER_ROLE } from '../../constants/user-role';

@Injectable({ scope: Scope.TRANSIENT })
export class LoggerService extends Logger {
  onUnauthorized(message: string, errorMessage?: string) {
    super.warn(`${AUTH.FAILED}: ${message ?? errorMessage}`);
    throw new UnauthorizedException(message);
  }

  onAuthorized(username: string, roles: Role[]) {
    super.log(`${AUTH.SUCCESS}: ${username} (${roles.join(', ')})`);
    return true;
  }

  onAuthorizedRole(username: string, role: Role) {
    super.log(`${AUTH.ROLE_SUCCESS}: ${username} (${role})`);
    return true;
  }

  onUnauthorizedRole(username: string, roles: Role[]) {
    super.warn(`${AUTH.ROLE_FAILED}: ${username} (${roles.join(', ')})`);
    throw new UnauthorizedException(AUTH.ROLE_FAILED);
  }

  onUserBadRequest(message: string, username?: string) {
    if (username) super.warn(`${message} (${username})`);
    else super.warn(message);
    throw new BadRequestException(message);
  }

  onInternalServerError(message: string, errorMessage?: string) {
    if (!errorMessage) super.error(message);
    else super.error(`${message}: ${errorMessage}`);

    throw new InternalServerErrorException(INTERNAL_SERVER_ERROR);
  }

  onPingSuccess() {
    super.log(PONG);
    return {
      statusCode: HttpStatus.OK,
      PONG,
    };
  }

  onUserSuccess(
    message: string,
    username: string,
    statusCode: HttpStatus = HttpStatus.CREATED,
  ) {
    super.log(`${message} (${username})`);
    return {
      statusCode,
      message: message,
    };
  }

  onUserRolesUpdateSuccess(
    triggeredByUsername: string,
    targetUsername: string,
    userRoleAction: UserRoleAction,
    roles: Role[],
  ) {
    const message =
      userRoleAction === UserRoleAction.ADD
        ? USER_ROLE.ADDED
        : USER_ROLE.REMOVED;

    super.log(
      `${message}: ${triggeredByUsername} -> ${targetUsername} (${roles.join(', ')})`,
    );
    return {
      statusCode: HttpStatus.CREATED,
      message,
    };
  }

  onUnhandledError(exception: unknown) {
    super.error(exception);
  }
}
