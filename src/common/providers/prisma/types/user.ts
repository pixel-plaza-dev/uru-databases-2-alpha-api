import { User, UserEmail } from '@prisma/client';

export type UserCreatePartial = Partial<
  Pick<User, 'address' | 'phone' | 'birthDate'>
>;

export type UserCreateRequired = Pick<
  User,
  'username' | 'password' | 'firstName' | 'lastName'
> &
  Pick<UserEmail, 'email'>;

export type UserCreate = UserCreateRequired & UserCreatePartial;

export type UserUpdate = Partial<
  Pick<User, 'firstName' | 'lastName' | 'address' | 'phone' | 'birthDate'>
>;
