export enum Validation {
  Offline = 'Offline',
  Online = 'Online',
}

export interface KeycloakOptions {
  url: string;
  realm: string;
  clientId: string;
  tokenValidation: Validation;
}

export interface KeycloakPathReturn {
  issuer: string,
  jwksUri: string,
  rpt: string,
  entitlement: string,
}

export function KeycloakPath(url: string, realm: string, clientId: string): KeycloakPathReturn {
  return {
    issuer: `${url}/auth/realms/${realm}`,
    jwksUri: `${url}/auth/realms/${realm}/protocol/openid-connect/certs`,
    rpt: `${url}/auth/realms/${realm}/protocol/openid-connect/token`,
    entitlement: `${url}/auth/realms/${realm}/authz/entitlement/${clientId}`
  }
}
