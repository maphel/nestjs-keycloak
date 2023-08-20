export interface KeycloakOptions {
  issuer: string; // The URL of the Keycloak server's issuer
  clientId: string; // The client ID for your application
  jwksUri: string; // The URI to retrieve the JSON Web Key Set for token verification
}
