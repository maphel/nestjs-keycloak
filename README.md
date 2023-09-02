# NestJS Keycloak Integration

- [NestJS Keycloak Integration](#nestjs-keycloak-integration)
    - [Installation](#installation)
- [Getting Started](#getting-started)
    - [Import KeycloakModule](#1-import-keycloakmodule)
    - [Protect Routes with @Roles, @Scopes, and @Resources](#protect-routes-with-roles-scopes-and-resources)
- [Features](#features)
- [License](#license)
- 
This package provides easy integration of Keycloak authentication and authorization into your NestJS application. It allows you to secure your APIs with roles, scopes, and resources defined in your Keycloak realm.

## Installation

## work in progress!!

Install the package using npm:

```bash
npm install nestjs-keycloak // not published atm
```
# Getting Started

## Import KeycloakModule
   In your application module, import and register the KeycloakModule with your Keycloak options.

```typescript
import { Module } from '@nestjs/common';
import { KeycloakModule } from 'nestjs-keycloak';
import { AppController } from './app.controller';
import { AppService } from './app.service';

const keycloakOptions: KeycloakOptions = {
  url: 'YOUR_KEYCLOAK_URL',
  realm: 'YOUR_REALM',
  clientId: 'YOUR_CLIENT_ID',
  secret: 'YOUR_SECRET',
  tokenValidation: Validation.Online // of Offline
};

@Module({
  imports: [
    KeycloakModule.register(keycloakOptions),
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
```

## Protect Routes with @Roles, @Scopes, and @Resources
```typescript
import { Controller, Get, UseGuards } from '@nestjs/common';
import { KeycloakGuard, Roles, Scopes, Resources } from 'nestjs-keycloak';

@Controller('protected')
@UseGuards(KeycloakGuard)
@Resources('resource1') // Secure hole controller with required resources
export class ProtectedController {
  @Get('admin')
  @Roles('admin') // Secure route with required roles
  async adminRoute() {
    // Your admin logic here
  }

  @Get('read-data')
  @Scopes('read:data') // Secure route with required scopes
  async readDataRoute() {
    // Your read data logic here
  }

  @Get('resource')
  @Resources('resource1') // Secure route with required resources
  async resourceRoute() {
    // Your resource logic here
  }
}
```

## Features
- Authentication: Verify tokens and ensure valid authentication.
- Authorization: Protect routes based on roles, scopes, and resources.
- Dynamic Module: Easy integration through dynamic module registration.
- Configurable Options: Customize integration based on your Keycloak configuration.

## License

This package is released under the [MIT License](LICENSE).

