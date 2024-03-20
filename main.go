package main

import (
	"flag"
	"fmt"
	"log"
)

func seedAccount(store Storage, firstName, lastName, password string) *Account {
	acc, err := newAccount(firstName, lastName, password)
	if err != nil {
		log.Fatal(err)
	}

	if store.CreateAccount(acc); err != nil {
		log.Fatal(err)
	}

	fmt.Println("new account => ", acc.Number)

	return acc
}

func seedAccounts(s Storage) {
	seedAccount(s, "Victor", "Sena", "test")
}

func main() {
	seed := flag.Bool("seed", false, "seed the db")
	flag.Parse()

	store, err := newPostgresStore()
	if err != nil {
		log.Fatal(err)
	}

	if err := store.Init(); err != nil {
		log.Fatal(err)
	}

	if *seed {
		fmt.Println("seeding the database")
		// seed stuff
		seedAccounts(store)
	}

	server := NewApiServer(":3000", store)
	server.Run()
}
