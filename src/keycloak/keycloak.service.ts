import { Injectable, Inject, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { KeycloakOptions } from './keycloak.options';
import fetch from 'node-fetch';
import {jwtVerify, JWTVerifyResult, KeyLike} from "jose";

@Injectable()
export class KeycloakService {
  constructor(
    @Inject('KEYCLOAK_OPTIONS') private options: KeycloakOptions,
  ) {}

  private async getKey(): Promise<KeyLike> {
    // Fetch the JWKS from the Keycloak server
    const response = await fetch(this.options.jwksUri);
    const jwks = await response.json();
    return asKey(jwks.keys[0]); // Selecting the first key, but you might want to match the key by ID
  }

  async verifyToken(token: string): Promise<JWTVerifyResult> {
    const key = await this.getKey();
    try {
      return await jwtVerify(token, key, {
        issuer: this.options.issuer,
        audience: this.options.clientId,
      });
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  validateScopes(payload: any, requiredScopes: string[]): boolean {
    const scopes = payload.scope?.split(' ') || [];
    return requiredScopes.every(scope => scopes.includes(scope));
  }

  validateRoles(payload: any, requiredRoles: string[]): boolean {
    const roles = payload.realm_access?.roles || [];
    return requiredRoles.every(role => roles.includes(role));
  }


  // You can include additional methods related to Keycloak as needed
}
