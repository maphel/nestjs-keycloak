import {Inject, Injectable, UnauthorizedException} from '@nestjs/common';
import {KeycloakOptions, KeycloakPath, KeycloakPathReturn, Validation} from './keycloak.options';
import fetch from 'node-fetch';
import {JWK, jwtVerify, JWTVerifyResult, KeyLike} from 'jose';

@Injectable()
export class KeycloakService {
  private keyCloakPath: KeycloakPathReturn;
  private keyCache: { [kid: string]: { key: KeyLike, expireAt: number } } = {};

  constructor(
    @Inject('KEYCLOAK_OPTIONS') private options: KeycloakOptions,
  ) {
    this.keyCloakPath = KeycloakPath(this.options.url, this.options.realm, this.options.clientId);
  }

  private async getKey(kid: string, expiresIn: number): Promise<KeyLike> {
    const now = Date.now();
    if (this.options.tokenValidation === Validation.Offline && this.keyCache[kid] && this.keyCache[kid].expireAt > now) {
      return this.keyCache[kid].key;
    }
    const response = await fetch(this.keyCloakPath.jwksUri);
    if (!response.ok) {
      throw new UnauthorizedException('Failed to fetch JWKS');
    }
    const jwks = await response.json();
    const keyObj = jwks.keys.find((key: { kid: string }) => key.kid === kid);
    if (!keyObj) {
      throw new UnauthorizedException('Key not found');
    }
    const key = JWK.asKey(keyObj);
    this.keyCache[kid] = {key, expireAt: now + (expiresIn * 1000)};
    return key;
  }

  async verifyToken(token: string): Promise<JWTVerifyResult> {
    const headerBase64 = token.split('.')[0];
    const headerJson = Buffer.from(headerBase64, 'base64').toString('utf-8');
    const {kid, expires_in} = JSON.parse(headerJson);

    const key = await this.getKey(kid, expires_in);
    try {
      return await jwtVerify(token, key, {
        issuer: this.keyCloakPath.issuer,
        audience: this.options.clientId,
      });
    } catch (error) {
      delete this.keyCache[kid];
      throw new UnauthorizedException('Invalid token');
    }
  }

  async validateScopes(token: string, scopes: string[]): Promise<boolean> {
    const payload = await this.verifyToken(token);
    if (this.options.tokenValidation === Validation.Online) {
      return await this.validateScopesOnline(token, scopes)
    }
    return this.validateScopesOffline(payload, scopes);
  }

  async validateRoles(token: string, requiredRoles: string[]): Promise<boolean> {
    const payload = await this.verifyToken(token);
    const roles = payload.realm_access?.roles || [];
    return requiredRoles.every(role => roles.includes(role));
  }

  private async validateScopesOnline(token: string, scopes: string[]): Promise<boolean> {
    const rpt = await this.getRPT(token);
    const rptPayload = await this.verifyToken(rpt);
    const permissions = rptPayload.authorization?.permissions || [];
    const permissionScopes = permissions.map(p => p.scopes).flat();
    return scopes.every(scope => permissionScopes.includes(scope));
  }

  private validateScopesOffline(payload: any, scopes: string[]): boolean {
    const jwtScopes = payload.scope?.split(' ') || [];
    return jwtScopes.every(scope => scopes.includes(scope));
  }

  public async validateResources(token: string, resources: string[]): Promise<boolean> {
    const payload = await this.verifyToken(token);
    if (this.options.tokenValidation === Validation.Online) {
      return await this.validateResourcesOnline(token, resources)
    }
    return this.validateResourcesOffline(payload, resources);
  }

  private validateResourcesOffline(payload: any, requiredResources: string[]): boolean {
    const userResources = payload.resource_access?.['your-client'].resources || [];
    return requiredResources.every(resource => userResources.includes(resource));
  }

  private async validateResourcesOnline(token: string, requiredResources: string[]): Promise<boolean> {
    const rptToken = await this.getRPT(token);
    const headers = {
      'Authorization': `Bearer ${rptToken}`,
    };
    const response = await fetch(this.keyCloakPath.entitlement, {method: 'GET', headers});
    const data = await response.json();

    const permissions = data.authorization?.permissions || [];
    return requiredResources.every(resource => permissions.some(p => p.rsid === resource));
  }


  private async getRPT(accessToken: string): Promise<string> {
    const headers = {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    };

    const params = new URLSearchParams();
    params.append('grant_type', 'urn:ietf:params:oauth:grant-type:uma-ticket');
    const response = await fetch(this.keyCloakPath.rpt, {method: 'POST', headers, body: params});
    const data = await response.json();
    return data.rpt;
  }
}
