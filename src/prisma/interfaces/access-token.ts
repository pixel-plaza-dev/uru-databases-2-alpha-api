export interface AccessTokenCreate {
  token: string;
  expiresAt: Date;
  refreshToken: string;
}

export interface AccessTokenSelectable {
  id?: boolean;
  token?: boolean;
  expiresAt?: boolean;
  createdAt?: boolean;
  lastUsedAt?: boolean;
  revokedAt?: boolean;
}
