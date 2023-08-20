import {KeycloakService} from "./keycloak.service";
import {CanActivate, ExecutionContext, Injectable} from "@nestjs/common";
import {Reflector} from "@nestjs/core";
import {RESOURCES_KEY, ROLES_KEY, SCOPES_KEY} from "./keycloak.decorator";

@Injectable()
export class KeycloakGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private keycloakService: KeycloakService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const roles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [context.getHandler(), context.getClass()]);
    const scopes = this.reflector.getAllAndOverride<string[]>(SCOPES_KEY, [context.getHandler(), context.getClass()]);
    const resources = this.reflector.getAllAndOverride<string[]>(RESOURCES_KEY, [context.getClass()]);
    const request = context.switchToHttp().getRequest();

    const token = request.headers.authorization;
    const payload = await this.keycloakService.verifyToken(token);

    if (roles && !this.keycloakService.validateRoles(payload, roles)) return false;
    if (scopes && !this.keycloakService.validateScopes(payload, scopes)) return false;
    if (resources && !this.keycloakService.checkResources(payload, resources)) return false;

    return true;
  }
}
