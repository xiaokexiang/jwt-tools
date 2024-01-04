## jwt tools
> Tools for generating RAS certificates and generating and parsing JWT Token

### Usage method
```bash
$ go build -o jwt
$ ./jwt help
Usage: <command> [options]
Commands:
  enc      Encrypt JWT tokens
  dec      Decrypt JWT tokens
  cert     Generate public and private keys
$ ./jwt cert
Usage of cert:
  -export
        Export public and private keys to files (default: export to file)
  -path string
        Path to the directory where the keys will be exported. (default ".")
$ ./jwt enc
Usage of enc:
  -exp int
        Expiration time of the JWT in seconds (default 3600)
  -iss string
        Issuer of the JWT
  -private string
        Path to the private key file (default "./private_key.pem")
  -sub string
        Subject of the JWT (default "test jwk")
$ ./jwt dec 
Usage of dec:
  -path string
        Path to the public key file (default "./public_key.pem")
  -token string
        jwt token to be decrypted

```