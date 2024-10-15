package main

import (
	"database/sql"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	mrand "math/rand"

	_"github.com/mattn/go-sqlite3"
	"github.com/atotto/clipboard"
	"github.com/joho/godotenv"
)

var encryptionKey []byte

func main() {
  // Load the .env file
     err := godotenv.Load()
     if err != nil {
         log.Fatalf("Error loading .env file: %s", err)
     }
 
     // Get the encryption key from the environment
     encryptionKeyStr := os.Getenv("ENCRYPTION_KEY")
     encryptionKey = []byte(encryptionKeyStr)
    
	db, err := initDB()
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var chosenOption int

	for {
		fmt.Println("1. Add password | 2. Get password | 3. List passwords | 4. Exit")
		fmt.Scanln(&chosenOption)

		switch chosenOption {
			case 1:
				addPassword(db)
			case 2:
				getPassword(db)
			case 3:
				listPasswords(db)
			case 4:
				fmt.Println("Exiting...")
				return
			default:
				fmt.Println("Invalid option")
		}
	}
}

func addPassword(db *sql.DB) {
	var label, password string
	var input int
	fmt.Print("Enter label: ")
	fmt.Scanln(&label)
	fmt.Println("1. Generate password | 2. Enter password")
	fmt.Scanln(&input)
	if input == 1 {
		fmt.Print("Enter password length: ")
		var length int
		fmt.Scanln(&length)
		password = generatePassword(length)
		password = encryptPassword(password)
	} else {
		fmt.Print("Enter password: ")
		fmt.Scanln(&password)
		password = encryptPassword(password)
	}

	_, err := db.Exec("INSERT INTO passwords (label, password) VALUES (?, ?)", label, password)
	if err != nil {
		fmt.Printf("Failed to insert password: %v\n", err)
		return
	}
	fmt.Println("Password added")
	return
}

func generatePassword(length int) string {
	fmt.Println("Generating password...")
	var chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,-!@#$%^&*()_+=<>?/{}[]|~"
	var password string
	for i := 0; i < length; i++ {
		password += string(chars[mrand.Intn(len(chars))])
	}
	return password
}

func getPassword(db *sql.DB) {
	var label, password string
	fmt.Print("Enter label: ")
	fmt.Scanln(&label)

	err := db.QueryRow("SELECT password FROM passwords WHERE label = ?", label).Scan(&password)
	if err != nil {
		fmt.Printf("Failed to get password: %v\n", err)
		return
	}
	var realPassword = decryptPassword(password)
	var passwordStars string
	for i := 0; i < len(realPassword); i++ {
		passwordStars += "*"
	}
	fmt.Printf("Password: %s\n", passwordStars)

	var input int

	for {
		fmt.Println("1. Show password | 2. Copy password | 3. Cancel")
		fmt.Scanln(&input)
		if input == 1 {
			fmt.Printf("Password: %s\n", realPassword)
		} else if input == 2 {
			err := clipboard.WriteAll(realPassword)
        if err != nil {
        	fmt.Printf("Failed to copy password to clipboard: %v\n", err)
        }
			fmt.Println("Password copied to clipboard")
		} else {
			return
		}
	}
	
	return
}

func listPasswords(db *sql.DB) {
	rows, err := db.Query("SELECT label, password FROM passwords")
	if err != nil {
		fmt.Printf("Failed to list passwords: %v\n", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var label, password string
		err := rows.Scan(&label, &password)
		if err != nil {
			fmt.Printf("Failed to read row: %v\n", err)
			return
		}
		var passwordStars string
		for i := 0; i < len(password); i++ {
			passwordStars += "*"
		}
		fmt.Printf("Label: %s, Password: %s\n", label, passwordStars)
	}

	err = rows.Err()
	if err != nil {
		fmt.Printf("Failed to list passwords: %v\n", err)
	}
	return
}

func initDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", "./mydb.sqlite")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS passwords (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			label TEXT NOT NULL,
			password TEXT UNIQUE NOT NULL
		)
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to create table: %v", err)
	}

	fmt.Println("Database initialized")

	return db, nil
}


func encryptPassword(password string) string {
	plaintext := []byte(password)

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return ""
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return ""
	}
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)

	return base64.StdEncoding.EncodeToString(ciphertext)
}

func decryptPassword(encryptedPassword string) string {
	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedPassword)
	if err != nil {
		return ""
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return ""
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return ""
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return ""
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return ""
	}

	return string(plaintext)
}