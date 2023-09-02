import { DynamicModule, Module, Global } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { KeycloakService } from './keycloak.service';
import { KeycloakOptions } from './keycloak.options';
import { KeycloakGuard } from './keycloak.guard';

@Global()
@Module({})
export class KeycloakModule {
  static register(options: KeycloakOptions): DynamicModule {
    return {
      imports: [],
      module: KeycloakModule,
      providers: [
        Reflector,
                {
          provide: 'KEYCLOAK_OPTIONS',
          useValue: options,
        },
        KeycloakService,
        KeycloakGuard,
      ],
      exports: [KeycloakService, KeycloakGuard, Reflector],
    };
  }
}
