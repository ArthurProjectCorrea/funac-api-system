import { IsString, IsOptional } from 'class-validator';

export class CreatePermissionDto {
  @IsString({ message: 'Nome da permissão é obrigatório' })
  name: string;

  @IsString({ message: 'Recurso é obrigatório' })
  resource: string;

  @IsString({ message: 'Ação é obrigatória' })
  action: string;

  @IsOptional()
  @IsString({ message: 'Descrição deve ser uma string' })
  description?: string;
}
