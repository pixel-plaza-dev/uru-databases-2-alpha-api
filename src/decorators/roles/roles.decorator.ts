import { SetMetadata } from '@nestjs/common';
import { ROLES_KEY } from '../../global/config';
import { Role } from '@prisma/client';

export const Roles = (...roles: Role[]) => SetMetadata(ROLES_KEY, roles);
