import {CanActivate, ExecutionContext, ForbiddenException, Injectable, UnauthorizedException} from "@nestjs/common";
import {KeycloakService} from "./keycloak.service";
import {Reflector} from "@nestjs/core";
import {AUTH_KEY, RESOURCES_KEY, ROLES_KEY, SCOPES_KEY} from "./keycloak.decorator";

@Injectable()
export class KeycloakGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private keycloakService: KeycloakService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const auth = this.reflector.getAllAndOverride<string[]>(AUTH_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    const request = context.switchToHttp().getRequest();
    const token = request.headers.authorization;

    if(auth) {
        try {
          await this.keycloakService.verifyToken(token);
        } catch (error) {
          throw new UnauthorizedException();
        }
    }

    const roles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (roles) {
      const hasValidRoles = await this.keycloakService.validateRoles(token, roles);
      if (!hasValidRoles) {
        throw new ForbiddenException('Insufficient roles');
      }
    }

    const resources = this.reflector.getAllAndOverride<string[]>(RESOURCES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (resources) {
      const hasValidResources = await this.keycloakService.validateResources(token, resources);
      if (!hasValidResources) {
        throw new ForbiddenException('Insufficient resources');
      }
    }

    const scopes = this.reflector.getAllAndOverride<string[]>(SCOPES_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (scopes) {
      const hasValidScopes = await this.keycloakService.validateScopes(token, scopes);
      if (!hasValidScopes) {
        throw new ForbiddenException('Insufficient scopes');
      }
    }

    return true;
  }
}
