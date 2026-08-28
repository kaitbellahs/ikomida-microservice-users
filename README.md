# ikomida-microservice-users

Accounts, authentication and addresses.

> Part of the **iKomida** platform. See **[ikomida-k8s-config](https://github.com/kaitbellahs/ikomida-k8s-config)** for the architecture overview of all 31 repositories.

---

## Role

Owns the user record and everything anchored to it: sign-up, login, password recovery, phone validation by SMS code, profile and avatar, and the delivery addresses a client orders to.

This is the service that holds the **private signing key** — it mints the JWTs that every other service verifies with the public half.

## Endpoints

As declared in the [gateway route table](https://github.com/kaitbellahs/ikomida-microservice-gateway/blob/dev/src/routes.ts) (18 routes reach this service):

| Method | Path | Roles |
|---|---|---|
| `GET` | `/usersCount` | VENDOR, STAFF |
| `GET` | `/settings` | CLIENT |
| `POST` | `/password` | ALL |
| `POST` | `/auth` | *public* |
| `DELETE` | `/deleteAccount` | ALL |
| `DELETE` | `/logout` | ALL |
| `POST` | `/requestPhoneValidation` | *public* |
| `POST` | `/requestPasswordPhoneValidation` | *public* |
| `POST` | `/validatePhoneValidationCode` | *public* |
| `POST` | `/validatePasswordPhoneValidationCode` | *public* |
| `POST` | `/subscribe` | *public* |
| `POST` | `/requestPassword` | *public* |
| `PATCH` | `/profile/avatar` | ALL |
| `GET` | `/profile` | ALL |
| `GET` | `/addresses` | CLIENT |
| `POST` | `/address` | CLIENT |
| `PUT` | `/address/:id` | CLIENT |
| `DELETE` | `/address/:id` | CLIENT |

## Stack

TypeScript (ESM) · Express · Sequelize · rollup · Docker · Kubernetes

Depends on [`@ikomida/shared-types`](https://github.com/kaitbellahs/ikomida-shared-types), [`@ikomida/shared-backend`](https://github.com/kaitbellahs/ikomida-shared-backend) and [`@ikomida/shared-logics`](https://github.com/kaitbellahs/ikomida-shared-logics).

## Build

```bash
yarn install
yarn build      # rollup bundle
yarn service    # run locally
```

## Status

Built in 2022. The platform is no longer deployed; this repository is published as a record of the work. **The commit history predates generative AI coding assistants.**

## License

Licensed under the [Apache License 2.0](LICENSE) — free for commercial use, provided the copyright notice and [NOTICE](NOTICE) are retained.

Copyright 2022 Khalid Ait Bellahs.
