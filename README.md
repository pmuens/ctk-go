# Cypherpunk Toolkit

Cryptographic primitives for [Cypherpunks](https://en.wikipedia.org/wiki/Cypherpunk) that don't subscribe to ["trust me bro"](https://en.wikipedia.org/wiki/Nothing-up-my-sleeve_number) [security assumptions](<https://en.wikipedia.org/wiki/Backdoor_(computing)>).

**Note:** The implementations in this repo shouldn't be used in a production environment as they are neither optimized (e.g. to combat constant-time attacks), nor audited.

## Setup

1. `git clone <url>`
2. `asdf install`
3. `go test -race ./...`

## Primitives

- Stream Cipher
  - ChaCha20 ([RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439))
- MAC
  - Poly1305 ([RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439))
- AEAD
  - ChaCha20-Poly1305 ([RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439))
  - XChaCha20 ([RFC draft-irtf-cfrg-xchacha-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03))
  - XChaCha20-Poly1305 ([RFC draft-irtf-cfrg-xchacha-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03))
- Hash
  - Blake2 ([RFC 7693](https://datatracker.ietf.org/doc/html/rfc7693))
- KDF
  - Argon2 ([RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106))
- Key Exchange
  - X25519 ([RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748))
- Digital Signatures
  - EdDSA (Blake2b + edwards25519) ([RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032))

## Useful Commands

```sh
go run <package-path>
go build [<package-path>]

go test [<package-path>][/...] [-v] [-cover] [-race] [-parallel <number>]
go test -bench=. [<package-path>] [-count <number>] [-benchmem] [-benchtime 2s] [-memprofile <name>]

go test -coverprofile <name> [<package-path>]
go tool cover -html <name>
go tool cover -func <name>

go doc [<package-path>]
go fmt [<package-path>]
go vet [<package-path>]

go mod init [<module-path>]
go mod tidy
go mod vendor
go mod download

go work init [<module-path-1> [<module-path-2>] [...]]
go work use [<module-path-1> [<module-path-2>] [...]]
go work sync

# Adjust dependencies in `go.mod`.
go get <package-path>[@<version>]

# Build and install commands.
go install <package-path>[@<version>]

go list -m [all]
```

## Useful Resources

- [Go - Learn](https://go.dev/learn)
- [Go - Documentation](https://go.dev/doc)
- [Go - A Tour of Go](https://go.dev/tour)
- [Go - Effective Go](https://go.dev/doc/effective_go)
- [Go - Playground](https://go.dev/play)
- [Go by Example](https://gobyexample.com)
- [100 Go Mistakes and How to Avoid Them](https://100go.co)
