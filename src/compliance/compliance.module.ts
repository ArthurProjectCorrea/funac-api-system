import { Module } from '@nestjs/common';
import { LgpdService } from './lgpd-simple.service';
import { DatabaseModule } from '../database/database.module';
import { AuditModule } from '../audit/audit.module';

@Module({
  imports: [DatabaseModule, AuditModule],
  providers: [LgpdService],
  exports: [LgpdService],
})
export class ComplianceModule {}
