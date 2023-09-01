import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'nestjs_keycloak_roles';
export const Roles = (...roles: string[]) => SetMetadata(ROLES_KEY, roles);

export const SCOPES_KEY = 'nestjs_keycloak_scopes';
export const Scopes = (...scopes: string[]) => SetMetadata(SCOPES_KEY, scopes);

export const RESOURCES_KEY = 'nestjs_keycloak_resources';
export const Resources = (...resources: string[]) => SetMetadata(RESOURCES_KEY, resources);

export const AUTH_KEY = 'nestjs_keycloak_auth';
export const Auth = (...resources: string[]) => SetMetadata(RESOURCES_KEY, resources);
