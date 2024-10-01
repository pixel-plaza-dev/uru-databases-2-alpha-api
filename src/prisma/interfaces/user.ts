export interface UserCreate {
  email: string;
  username: string;
  password: string;
  firstName: string;
  lastName: string;
  address?: string;
  phone?: string;
}

export interface UserSelectable {
  id?: boolean;
  email?: boolean;
  username?: boolean;
  password?: boolean;
  firstName?: boolean;
  lastName?: boolean;
  address?: boolean;
  phone?: boolean;
  deleted?: boolean;
  role?: boolean;
}
