import { IsString, IsOptional, IsArray } from 'class-validator';

export class CreateRoleDto {
  @IsString({ message: 'Nome do papel é obrigatório' })
  name: string;

  @IsOptional()
  @IsString({ message: 'Descrição deve ser uma string' })
  description?: string;

  @IsOptional()
  @IsArray({ message: 'Permissões deve ser um array' })
  @IsString({ each: true, message: 'Cada permissão deve ser uma string' })
  permissionIds?: string[];
}
