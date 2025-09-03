import { Injectable, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

@Injectable()
export class TokenBlacklistService {
  private readonly accessTokenTtl: number;

  constructor(
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private configService: ConfigService,
  ) {
    // TTL deve ser o mesmo do access token (15 min por padrão)
    this.accessTokenTtl = this.configService.get<number>(
      'ACCESS_TOKEN_BLACKLIST_TTL',
      900000, // 15 minutos em ms
    );
  }

  /**
   * Adiciona um token à blacklist
   */
  async blacklistToken(tokenId: string, expiresAt: Date): Promise<void> {
    const ttl = Math.max(0, expiresAt.getTime() - Date.now());

    if (ttl > 0) {
      await this.cacheManager.set(`blacklist:${tokenId}`, true, ttl);
    }
  }

  /**
   * Verifica se um token está na blacklist
   */
  async isTokenBlacklisted(tokenId: string): Promise<boolean> {
    const result = await this.cacheManager.get(`blacklist:${tokenId}`);
    return !!result;
  }

  /**
   * Remove um token da blacklist (normalmente não necessário devido ao TTL)
   */
  async removeFromBlacklist(tokenId: string): Promise<void> {
    await this.cacheManager.del(`blacklist:${tokenId}`);
  }

  /**
   * Adiciona múltiplos tokens à blacklist (útil para logout de todas as sessões)
   */
  async blacklistMultipleTokens(
    tokens: Array<{ id: string; expiresAt: Date }>,
  ): Promise<void> {
    const promises = tokens.map((token) =>
      this.blacklistToken(token.id, token.expiresAt),
    );

    await Promise.all(promises);
  }

  /**
   * Limpa toda a blacklist (usar com cuidado)
   */
  async clearBlacklist(): Promise<void> {
    // Como estamos usando TTL, os tokens expiram automaticamente
    // Este método é mais para testes/admin
    // Cache manager do NestJS não tem reset, então vamos ignorar por enquanto
    // Para implementação completa, seria necessário usar Redis diretamente
  }

  /**
   * Obtém estatísticas da blacklist
   */
  getBlacklistStats(): {
    totalBlacklisted: number;
    ttlConfigured: number;
  } {
    // Cache manager do NestJS não expõe contadores nativamente
    // Implementação básica
    return {
      totalBlacklisted: 0, // Placeholder - implementar se necessário
      ttlConfigured: this.accessTokenTtl,
    };
  }
}
