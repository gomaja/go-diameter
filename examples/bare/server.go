// Copyright 2013-2014 go-diameter authors.  All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Experimental diameter server that currently does nothing but print
// incoming messages.
package main

import (
	"log"
	"net"

	"github.com/gomaja/go-diameter/diam"
	"github.com/gomaja/go-diameter/diam/dict"
)

func main() {
	dictionary, err := dict.New(dict.Base())
	if err != nil {
		log.Fatal(err)
	}
	if err := dictionary.LoadFile("diam_app.xml"); err != nil {
		log.Fatal(err)
	}
	srv, err := net.Listen("tcp", ":3868")
	if err != nil {
		panic(err)
	}
	for {
		if conn, err := srv.Accept(); err != nil {
			panic(err)
		} else {
			go handleClient(conn, dictionary)
		}
	}
}

func handleClient(conn net.Conn, dictionary *dict.Parser) {
	defer func() {
		if err := conn.Close(); err != nil {
			log.Printf("close connection: %v", err)
		}
	}()
	for {
		m, err := diam.ReadMessage(conn, dictionary)
		if err != nil {
			log.Fatal(err)
		}
		log.Println(m)
	}
}
