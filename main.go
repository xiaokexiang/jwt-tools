package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"os"
	"path/filepath"
	"time"
)

func main() {
	Parse()
}

const (
	ENCRYPT = "enc"
	DECRYPT = "dec"
	CERT    = "cert"
)

func Parse() {
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Println("Usage: <command> [options]")
		fmt.Println("Commands:")
		fmt.Println("  enc      Encrypt JWT tokens")
		fmt.Println("  dec      Decrypt JWT tokens")
		fmt.Println("  cert     Generate public and private keys")
	}
	command := flag.Arg(0)
	// 解析子参数
	subCommand := flag.NewFlagSet(command, flag.ExitOnError)
	switch command {
	case CERT:
		export := subCommand.Bool("export", true, "Export public and private keys to files (default: export to file)")
		exportPath := subCommand.String("path", ".", "Path to the directory where the keys will be exported.")
		_ = subCommand.Parse(flag.Args()[1:])
		privateKey, publicKey, _ := generateRSAKeyPair()
		if *export {
			exportToFile(*exportPath, privateKey, publicKey)
		} else {
			exportToString(privateKey, publicKey)
		}
	case ENCRYPT:
		iss := subCommand.String("iss", "", "Issuer of the JWT")
		sub := subCommand.String("sub", "test jwk", "Subject of the JWT")
		private := subCommand.String("private", "./private_key.pem", "Path to the private key file")
		exp := subCommand.Int("exp", 3600, "Expiration time of the JWT in seconds")
		_ = subCommand.Parse(flag.Args()[1:])
		generateJWTToken(*private, *iss, *sub, time.Duration(*exp)*time.Second)
	case DECRYPT:
		token := subCommand.String("token", "", "jwt token to be decrypted")
		public := subCommand.String("path", "./public_key.pem", "Path to the public key file")
		_ = subCommand.Parse(flag.Args()[1:])
		if *token == "" {
			subCommand.Usage()
			os.Exit(1)
		}
		parseJWTToken(*token, *public)
	default:
		fmt.Println("Usage: <command> [options]")
		fmt.Println("Commands:")
		fmt.Println("  enc      Encrypt JWT tokens")
		fmt.Println("  dec      Decrypt JWT tokens")
		fmt.Println("  cert     Generate public and private keys")
		os.Exit(1)
	}
}

func loadFile(path string, private bool) any {
	file, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("Read privateKey from %s error: %s\n", path, err)
	}
	if private {
		privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(file)
		if err != nil {
			log.Fatalf("Parse privateKey error: %s\n", err)
		}
		return privateKey
	} else {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM(file)
		if err != nil {
			log.Fatalf("Parse publicKey error: %s\n", err)
		}
		return publicKey
	}
}

func generateJWTToken(privateKeyPath, issuer, subject string, expiration time.Duration) {
	token := jwt.New(jwt.SigningMethodRS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["iss"] = issuer
	claims["sub"] = subject
	claims["exp"] = time.Now().Add(expiration).Unix()

	tokenString, err := token.SignedString(loadFile(privateKeyPath, true))
	if err != nil {
		log.Fatalf("Encrypt JWT tokens error: %s\n", err)
	}
	log.Printf("token: %s\n", tokenString)
}

func parseJWTToken(tokenString, publicKeyPath string) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return loadFile(publicKeyPath, false), nil
	})
	if err != nil {
		log.Fatalf("Parsing JWT error: %s\n", err)
	}
	if token.Valid {
		resp, err := json.MarshalIndent(token.Claims, "", "    ")
		if err != nil {
			log.Fatalf("Marshaling claims to JSON error: %s\n", err)
		}
		log.Printf("claims: %s\n", resp)
	} else {
		log.Fatalf("Invaild jwt token")
	}
}

func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("Generate public and private keys error: %s\n", err)
	}
	return privateKey, &privateKey.PublicKey, nil
}

func exportToString(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)

	log.Printf("privateKey: %s\n", base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})))
	log.Printf("publicKey: %s\n", base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})))
}

func exportToFile(path string, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) {
	err := os.MkdirAll(path, os.ModePerm)
	if err != nil {
		log.Fatalf("Error creating export folder: %s\n", err)
	}
	privateKeyPath := filepath.Join(path, "private_key.pem")
	publicKeyPath := filepath.Join(path, "public_key.pem")

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)

	if err := os.WriteFile(privateKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}), 0600); err != nil {
		log.Fatalf("export to path: %s error: %s\n", privateKeyPath, err)
	}
	if err := os.WriteFile(publicKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	}), 0600); err != nil {
		log.Fatalf("export to path: %s error: %s\n", publicKeyPath, err)
	}
	log.Printf("export cert to %s success!\n", path)
}
