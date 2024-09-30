export interface RefreshTokenCreate {
  email: string;
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
