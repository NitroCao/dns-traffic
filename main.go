/*
 * Copyright © 2019 JayceCao
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	_ "net/http/pprof"

	"net/http"

	"github.com/google/gopacket/pcap"
	"gopkg.in/urfave/cli.v1"
	"log"
	"os"
	"time"
)

const (
	dbName       = "DnsTraffic"
	dbCollection = "TrafficData"
	dbTimeout    = 10 * time.Second
	dateLayout   = "2006-01-02"
)

var (
	dev          string
	snapshotLen  int
	promiscuous  bool
	timeout      int
	prefix       string
	outputHandle output
	mongoURI     string
	stdout       bool
	err          error
	handle       *pcap.Handle
)

func main() {
	app := cli.NewApp()

	app.Name = "dns-traffic"
	app.Usage = "Log DNS query records in your computer"
	app.Description = "Log DNS query records in your computer"
	app.Author = "JayceCao <jaycecao520@gmail.com>"
	app.Version = "v0.1.0"
	app.Commands = commands

	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}
