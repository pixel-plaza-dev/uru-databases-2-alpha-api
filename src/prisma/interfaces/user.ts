export interface UserCreate {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  address?: string;
  phone?: string;
}

export interface UserSelectable {
  id?: boolean;
  password?: boolean;
  name?: boolean;
  address?: boolean;
  phone?: boolean;
  email?: true;
}
