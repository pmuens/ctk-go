# XChaCha20-Poly1305

A fully [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) and [RFC draft-irtf-cfrg-xchacha-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03) compliant implementation of the [XChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) AEAD algorithm.

[XChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) combines the [ChaCha20](https://muens.io/chacha20) stream cipher with the [Poly1305](https://muens.io/poly1305) message authentication code (MAC).

Both components and their extensions were implemented as self-contained units, so you can e.g. use [ChaCha20](https://muens.io/chacha20) without [Poly1305](https://muens.io/poly1305) if you want to.

Looking into the tests you'll find full coverage of all RFC test vectors which makes this implementation compliant with both RFCs.

**Note:** While you could in theory use these implementations as drop-in replacements, you probably shouldn't. The code was written for educational purposes and is therefore neither optimized (e.g. to combat timing attacks), nor audited.

## Setup

1. `git clone <url>`
2. `asdf install`
3. `go test -race ./...`
4. `go run ./cmd/cli/main.go`

## Primitives

### Stream Cipher

The [ChaCha20](./pkg/chacha20/) stream cipher and its variant [XChaCha20](./pkg/xchacha20/) (with [HChaCha20](./pkg/xchacha20/)).

### Message Authenticate Code

The [Poly1305](./pkg/poly1305/) message authentication code (MAC).

### Authenticated Encryption with Associated Data

The [ChaCha20-Poly1305](./pkg/chacha20poly1305/) AEAD construction alongside its variant [XChaCha20-Poly1305](./pkg/xchacha20poly1305/).

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
