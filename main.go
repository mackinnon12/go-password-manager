package main

import (
	"database/sql"
	"fmt"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

func main() {
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
	fmt.Print("Enter label: ")
	fmt.Scanln(&label)
	fmt.Print("Enter password: ")
	fmt.Scanln(&password)
	
	_, err := db.Exec("INSERT INTO passwords (label, password) VALUES (?, ?)", label, password)
	if err != nil {
		fmt.Printf("Failed to insert password: %v\n", err)
		return
	}
	fmt.Println("Password added")
	return
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
	fmt.Printf("Password: %s\n", password)
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
		fmt.Printf("Label: %s, Password: %s\n", label, password)
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


