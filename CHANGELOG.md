

## [0.10.1](https://github.com/brc-dd/iron-webcrypto/compare/v0.10.0...v0.10.1) (2023-09-01)


### Bug Fixes

* **deno:** types not being pickup ([f0793da](https://github.com/brc-dd/iron-webcrypto/commit/f0793da3bf603594d1b3a98a699e4554ac8f44ca))

## [0.10.0](https://github.com/brc-dd/iron-webcrypto/compare/v0.9.0...v0.10.0) (2023-09-01)

## [0.9.0](https://github.com/brc-dd/iron-webcrypto/compare/v0.8.2...v0.9.0) (2023-09-01)


### Bug Fixes

* **types:** prevent false ts errors with node webcrypto ([a0f1b6e](https://github.com/brc-dd/iron-webcrypto/commit/a0f1b6eac53a7b591c24f4166aaf6874cbb0c203))

## [0.8.2](https://github.com/brc-dd/iron-webcrypto/compare/v0.8.1...v0.8.2) (2023-08-29)

## [0.8.1](https://github.com/brc-dd/iron-webcrypto/compare/v0.8.0...v0.8.1) (2023-08-29)

## [0.8.0](https://github.com/brc-dd/iron-webcrypto/compare/0.7.1-5-ge4563a832d3b1670a963190f77822297c703eaeb...v0.8.0) (2023-07-17)

## [0.7.1](https://github.com/brc-dd/iron-webcrypto/compare/0.7.0...0.7.1) (2023-06-26)

## [0.7.0](https://github.com/brc-dd/iron-webcrypto/compare/0.6.0...0.7.0) (2023-04-22)

## [0.6.0](https://github.com/brc-dd/iron-webcrypto/compare/0.5.0...0.6.0) (2023-03-14)


### Bug Fixes

* **types:** emit .d.cts files and fix export map ([d1cb1e6](https://github.com/brc-dd/iron-webcrypto/commit/d1cb1e64da7444d9f87d06ce3af9fd5bd8609ea0))

## [0.5.0](https://github.com/brc-dd/iron-webcrypto/compare/0.4.0...0.5.0) (2023-02-11)

## [0.4.0](https://github.com/brc-dd/iron-webcrypto/compare/0.3.1...0.4.0) (2023-02-07)


### Features

* drop dependency on buffer and use standard uint8array ([#5](https://github.com/brc-dd/iron-webcrypto/issues/5)) ([285bfd9](https://github.com/brc-dd/iron-webcrypto/commit/285bfd962553cc6996562887271ac5350a8b7028))

## [0.3.1](https://github.com/brc-dd/iron-webcrypto/compare/0.3.0...0.3.1) (2023-02-07)


### Bug Fixes

* group exports to default ([45f96d5](https://github.com/brc-dd/iron-webcrypto/commit/45f96d50901097056d1382740db424aa3d492971))

## [0.3.0](https://github.com/brc-dd/iron-webcrypto/compare/0.2.7...0.3.0) (2023-02-07)


### Bug Fixes

* don't polyfill buffer on node ([#4](https://github.com/brc-dd/iron-webcrypto/issues/4)) ([421c853](https://github.com/brc-dd/iron-webcrypto/commit/421c85378785130b93ac13848827d7e850e641fe))

## [0.2.7](https://github.com/brc-dd/iron-webcrypto/compare/0.2.6...0.2.7) (2022-12-17)


### Bug Fixes

* reorder exports to move types to top ([e3bb1cb](https://github.com/brc-dd/iron-webcrypto/commit/e3bb1cbe4dd465c4a29c335577dea06b7775210c))

## [0.2.6](https://github.com/brc-dd/iron-webcrypto/compare/0.2.5...0.2.6) (2022-11-20)

## [0.2.5](https://github.com/brc-dd/iron-webcrypto/compare/0.2.4...0.2.5) (2022-09-09)


### Bug Fixes

* return null if decrypted string is empty ([a87ed60](https://github.com/brc-dd/iron-webcrypto/commit/a87ed601aacd342d287c1ccf1b92dd1fec047d7c))


### Performance Improvements

* use interfaces instead of types ([e898dbf](https://github.com/brc-dd/iron-webcrypto/commit/e898dbf2138549f253117a0d6b500bd5b0332ea5))

## [0.2.4](https://github.com/brc-dd/iron-webcrypto/compare/0.2.3...0.2.4) (2022-09-01)


### Bug Fixes

* include module bundle ([029bca0](https://github.com/brc-dd/iron-webcrypto/commit/029bca0d91984114319ac2db7b8348adc81c3470))

## [0.2.3](https://github.com/brc-dd/iron-webcrypto/compare/0.2.2...0.2.3) (2022-09-01)


### Bug Fixes

* typo in exports field ([0cd9032](https://github.com/brc-dd/iron-webcrypto/commit/0cd9032f14327775fff2ce4e06c502f4e2b764c1))

## [0.2.2](https://github.com/brc-dd/iron-webcrypto/compare/0.2.1...0.2.2) (2022-08-28)

## [0.2.1](https://github.com/brc-dd/iron-webcrypto/compare/0.2.0...0.2.1) (2022-08-28)


### Performance Improvements

* externalize buffer and re-export all types ([df68feb](https://github.com/brc-dd/iron-webcrypto/commit/df68feb7d8bcfffe7f66769c15821ece1c2f1d47))

## [0.2.0](https://github.com/brc-dd/iron-webcrypto/compare/0.1.0...0.2.0) (2022-08-27)

## [0.1.0](https://github.com/brc-dd/iron-webcrypto/compare/0.0.2...0.1.0) (2022-06-08)

### Features

- rely on manual dependency injection
  ([2c79346](https://github.com/brc-dd/iron-webcrypto/commit/2c793463c7dffb56e4fa13ac66af063adc745771))

### [0.0.2](https://github.com/brc-dd/iron-webcrypto/compare/0.0.1...0.0.2) (2022-06-08)

### Bug Fixes

- make esbuild think @peculiar/webcrypto is external
  ([fe10385](https://github.com/brc-dd/iron-webcrypto/commit/fe1038559b078e06b9fbdf2844759a1db759e7ad))

### 0.0.1 (2022-05-19)

### Features

- init
  ([984a515](https://github.com/brc-dd/iron-webcrypto/commit/984a515371c747a9528e0df90c8058ee232fc5cc))