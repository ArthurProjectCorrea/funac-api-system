import { PartialType } from '@nestjs/mapped-types';
import { CreateUserDto } from './create-user.dto';
import {
  IsOptional,
  IsEnum,
  IsBoolean,
  IsArray,
  IsString,
} from 'class-validator';
import { UserStatus } from '@prisma/client';

export class UpdateUserDto extends PartialType(CreateUserDto) {
  @IsOptional()
  @IsEnum(UserStatus, { message: 'Status deve ser um valor válido' })
  status?: UserStatus;

  @IsOptional()
  @IsBoolean({ message: 'MFA deve ser um valor booleano' })
  mfaEnabled?: boolean;

  @IsOptional()
  @IsArray({ message: 'Papéis deve ser um array' })
  @IsString({ each: true, message: 'Cada papel deve ser uma string' })
  roleIds?: string[];
}
