export interface RefreshTokenCreate {
  username: string;
  token: string;
  expiresAt: Date;
}
