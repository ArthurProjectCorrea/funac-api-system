import {
  IsEmail,
  IsString,
  IsOptional,
  MinLength,
  IsEnum,
  IsArray,
} from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { UserStatus } from '@prisma/client';

export class CreateUserDto {
  @ApiProperty({
    description: 'Email do usuário',
    example: 'usuario@funac.gov.br',
    format: 'email',
  })
  @IsEmail({}, { message: 'Email deve ter um formato válido' })
  email: string;

  @ApiProperty({
    description: 'Senha do usuário',
    example: 'MinhaSenh@123',
    minLength: 12,
  })
  @IsString({ message: 'Senha é obrigatória' })
  @MinLength(12, { message: 'Senha deve ter pelo menos 12 caracteres' })
  password: string;

  @ApiPropertyOptional({
    description: 'Primeiro nome do usuário',
    example: 'João',
  })
  @IsOptional()
  @IsString({ message: 'Nome deve ser uma string' })
  firstName?: string;

  @ApiPropertyOptional({
    description: 'Sobrenome do usuário',
    example: 'Silva',
  })
  @IsOptional()
  @IsString({ message: 'Sobrenome deve ser uma string' })
  lastName?: string;

  @ApiPropertyOptional({
    description: 'Departamento do usuário',
    example: 'Recursos Humanos',
  })
  @IsOptional()
  @IsString({ message: 'Departamento deve ser uma string' })
  department?: string;

  @IsOptional()
  @IsEnum(UserStatus, { message: 'Status deve ser um valor válido' })
  status?: UserStatus;

  @IsOptional()
  @IsArray({ message: 'Papéis deve ser um array' })
  @IsString({ each: true, message: 'Cada papel deve ser uma string' })
  roleIds?: string[];
}
