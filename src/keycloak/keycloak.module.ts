import { DynamicModule, Module, Global } from '@nestjs/common';
import { KeycloakService } from './keycloak.service';
import { KeycloakOptions } from './keycloak.options';

@Global()
@Module({})
export class KeycloakModule {
  static register(options: KeycloakOptions): DynamicModule {
    return {
      module: KeycloakModule,
      providers: [
        {
          provide: 'KEYCLOAK_OPTIONS',
          useValue: options,
        },
        KeycloakService,
      ],
      exports: [KeycloakService],
    };
  }
}
