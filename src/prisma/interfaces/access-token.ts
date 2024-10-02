export interface AccessTokenCreate {
  token: string;
  expiresAt: Date;
  refreshToken: string;
}
