# uru-databases-2-alpha-api

Alpha version of the backend API for the URU Databases 2 project, built with NestJS (TypeScript) and Prisma on MongoDB.

**Note:** This repository is archived and read-only. The original README was the unmodified NestJS starter text.

## Features

- **`users`** — users module (controller, service, module).
- **`ping`** — ping/health endpoint module.
- **`common`** — shared guards, filters, decorators, DTOs, providers, utils and constants.
- **`config`** — token and server settings for JWT access/refresh tokens, email verification and password reset.

## Configuration

Configuration is read from environment variables: `DATABASE_URL`, `SERVER_PORT`, `NODE_ENV`, `JWT_SECRET`, `ACCESS_TOKEN`, `ACCESS_TOKEN_EXPIRES_IN_MINUTES`, `REFRESH_TOKEN`, `REFRESH_TOKEN_EXPIRES_IN_DAYS`, `EMAIL_VERIFICATION_EXPIRES_IN_HOURS`, `PASSWORD_RESET_EXPIRES_IN_MINUTES` and `BCRYPT_SALT_ROUNDS`. The Prisma schema is in `prisma/schema.prisma`.

## Development

```bash
npm install

npm run start        # run
npm run start:dev    # watch mode
npm run start:prod   # production (runs dist/main)

npm run test         # unit tests
npm run test:cov     # coverage
```

`npm run test:e2e` expects `test/jest-e2e.json`, which is not in the repository.

## License

`LICENSE` is the GNU General Public License v3.0. `package.json` declares `GPL-3.0-only`.
