export interface RefreshTokenCreate {
  username: string;
  token: string;
  expiresAt: Date;
}

export interface RefreshTokenSelectable {
  id?: boolean;
  token?: boolean;
  expiresAt?: boolean;
  createdAt?: boolean;
  valid?: boolean;
}
