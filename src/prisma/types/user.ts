import { User } from '@prisma/client';

export type UserCreate = Pick<
  User,
  | 'email'
  | 'username'
  | 'password'
  | 'firstName'
  | 'lastName'
  | 'address'
  | 'phone'
  | 'birthDate'
>;

export type UserUpdate = Pick<
  User,
  'firstName' | 'lastName' | 'address' | 'phone' | 'birthDate'
>;
