import { User } from '@prisma/client';

export type UserCreatePartial = Partial<
  Pick<User, 'address' | 'phone' | 'birthDate'>
>;

export type UserCreateRequired = Pick<
  User,
  'email' | 'username' | 'password' | 'firstName' | 'lastName'
>;

export type UserCreate = UserCreateRequired & UserCreatePartial;

export type UserUpdate = Partial<
  Pick<User, 'firstName' | 'lastName' | 'address' | 'phone' | 'birthDate'>
>;
