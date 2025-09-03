import { IsEnum, IsOptional, IsString, IsDateString } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export enum ComplianceRequestType {
  DATA_ACCESS = 'DATA_ACCESS',
  DATA_RECTIFICATION = 'DATA_RECTIFICATION',
  DATA_DELETION = 'DATA_DELETION',
  DATA_PORTABILITY = 'DATA_PORTABILITY',
  PROCESSING_OBJECTION = 'PROCESSING_OBJECTION',
}

export enum RequestStatus {
  PENDING = 'PENDING',
  IN_PROGRESS = 'IN_PROGRESS',
  COMPLETED = 'COMPLETED',
  REJECTED = 'REJECTED',
}

export class CreateComplianceRequestDto {
  @ApiProperty({
    enum: ComplianceRequestType,
    description: 'Tipo de solicitação LGPD',
  })
  @IsEnum(ComplianceRequestType)
  type: ComplianceRequestType;

  @ApiPropertyOptional({
    description: 'Justificativa ou detalhes adicionais',
  })
  @IsOptional()
  @IsString()
  justification?: string;

  @ApiPropertyOptional({
    description: 'Dados específicos solicitados (para DATA_ACCESS)',
  })
  @IsOptional()
  @IsString()
  specificData?: string;
}

export class UpdateComplianceRequestDto {
  @ApiPropertyOptional({
    enum: RequestStatus,
    description: 'Status da solicitação',
  })
  @IsOptional()
  @IsEnum(RequestStatus)
  status?: RequestStatus;

  @ApiPropertyOptional({
    description: 'Resposta do administrador',
  })
  @IsOptional()
  @IsString()
  adminResponse?: string;

  @ApiPropertyOptional({
    description: 'Data de conclusão',
  })
  @IsOptional()
  @IsDateString()
  completedAt?: string;
}

export class DataPortabilityDto {
  @ApiProperty({
    description: 'Formato desejado para exportação',
    enum: ['JSON', 'CSV', 'XML'],
  })
  @IsEnum(['JSON', 'CSV', 'XML'])
  format: string;

  @ApiPropertyOptional({
    description: 'Categorias de dados específicas',
    type: [String],
  })
  @IsOptional()
  @IsString({ each: true })
  categories?: string[];
}
