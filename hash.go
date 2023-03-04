package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"strings"
	"time"
)

const iterations = 10000

func hashPassword(password string) (string, error) {
	// Generate a random salt
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	// Generate the hash with the salt using PBKDF2
	hash := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)

	// Encode the salt and hash as base64 strings
	var b strings.Builder
	b.WriteString(base64.StdEncoding.EncodeToString(salt))
	b.WriteString(":")
	b.WriteString(base64.StdEncoding.EncodeToString(hash))

	return b.String(), nil
}

func verifyPassword(password, hashedPassword string) (bool, error) {
	// Split the hashed password into salt and hash
	parts := strings.Split(hashedPassword, ":")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid hashed password format")
	}

	// Decode the salt and hash from base64 strings
	salt, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil {
		return false, err
	}
	hash, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false, err
	}

	// Generate a hash with the same salt using PBKDF2
	testHash := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)

	// Compare the generated hash with the stored hash
	return subtle.ConstantTimeCompare(hash, testHash) == 1, nil
}

func main() {
	var password string
	fmt.Println("Write your password:")
	fmt.Scanln(&password)

	start := time.Now()
	hash, err := hashPassword(password)
	duration := time.Since(start)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Hashed password:", hash)
	fmt.Println("Hashing took", duration)

	// Verify a password
	fmt.Println("Write a password for verification:")
	fmt.Scanln(&password)

	start = time.Now()
	match, err := verifyPassword(password, hash)
	duration = time.Since(start)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	if match {
		fmt.Println("Password is valid")
	} else {
		fmt.Println("Invalid password")
	}
	fmt.Println("Verification took", duration)
}
