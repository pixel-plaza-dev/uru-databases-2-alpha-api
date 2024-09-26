import { OmitType } from '@nestjs/swagger';
import { UserDto } from './user.dto';

export class SignupUserDto extends OmitType(UserDto, ['id'] as const) {}
