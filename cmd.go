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
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"gopkg.in/urfave/cli.v1"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	runFlags = []cli.Flag{
		cli.StringFlag{
			Name:        "interface, i",
			Value:       "",
			Usage:       "Specify network interface",
			Destination: &dev,
		},
		cli.IntFlag{
			Name:        "snapshot, s",
			Value:       1600,
			Usage:       "Specify the length as bytes of snapshot",
			Destination: &snapshotLen,
		},
		cli.BoolFlag{
			Name:        "promiscuous, p",
			Usage:       "Enable promiscuous mode for interface",
			Destination: &promiscuous,
		},
		cli.IntFlag{
			Name:        "timeout, t",
			Value:       30,
			Usage:       "Specify the timeout as seconds",
			Destination: &timeout,
		},
		cli.StringFlag{
			Name:        "output, o",
			Usage:       "Dump data as json file named with prefix `PREFIX` and timestamp",
			Destination: &prefix,
		},
		cli.StringFlag{
			Name:        "mongo, m",
			Usage:       "Specify MongoDB URI",
			Destination: &mongoURI,
		},
		cli.BoolFlag{
			Name:        "stdout, d",
			Usage:       "Print data in stdout",
			Destination: &stdout,
		},
	}
	runAction = func(c *cli.Context) error {
		setInterface()
		setOutput()

		ch := make(chan bool)
		sig := make(chan os.Signal)
		waitGroup := &sync.WaitGroup{}

		waitGroup.Add(1)
		go run(ch, waitGroup)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		log.Printf("[INFO]: Received termination signal. Waiting for goroutines" +
			"to exit...")
		close(ch)
		waitGroup.Wait()
		log.Printf("[INFO]: Exit.")

		return nil
	}
	runCmd = cli.Command{
		Name:   "run",
		Usage:  "Run dns-traffic",
		Flags:  runFlags,
		Action: runAction,
	}

	commands = []cli.Command{
		runCmd,
	}
)

func setInterface() {
	if dev == "" {
		ifaces, err := net.Interfaces()
		if err != nil {
			log.Fatalf("[ERROR]: %s", err.Error())
		}
		if len(ifaces) == 0 {
			log.Fatal("[ERROR]: No usable network interface.")
		}

		dev = ifaces[0].Name
	} else {
		_, err := net.InterfaceByName(dev)
		if err != nil {
			log.Fatalf("[ERROR]: %s", err.Error())
		}
	}
	log.Printf("[INFO]: Using interface: %s", dev)
}

func setOutput() {
	if prefix != "" {
		outputHandle = &jsonFile{}
		outputHandle.Init(prefix)
	} else if mongoURI != "" {
		outputHandle = &mongoDB{}
		outputHandle.Init(mongoURI)
	} else {
		stdout = true
	}
}

func run(ch chan bool, wait *sync.WaitGroup) {
	defer wait.Done()
	handle, err = pcap.OpenLive(dev, int32(snapshotLen), promiscuous, time.Duration(timeout)*time.Second)
	if err != nil {
		log.Fatalf("[ERROR]: Failed to OpenLive on %s interface: %s", dev, err.Error())
	}
	defer handle.Close()

	waitGroup := &sync.WaitGroup{}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		select {
		case <-ch:
			waitGroup.Wait()
			return
		default:
			waitGroup.Add(1)
			go handlePacket(&packet, waitGroup)
		}
	}
}

func handlePacket(packet *gopacket.Packet, waitGroup *sync.WaitGroup) {
	defer waitGroup.Done()

	var (
		ethLayer layers.Ethernet
		ip4Layer layers.IPv4
		ip6Layer layers.IPv6
		tcpLayer layers.TCP
		udpLayer layers.UDP
		dnsLayer layers.DNS
		payload  gopacket.Payload
		SrcIP    string
		DstIP    string
		SrcPort  uint16
		DstPort  uint16
	)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&ethLayer, &ip4Layer, &ip6Layer, &tcpLayer, &udpLayer, &dnsLayer, &payload)
	layerTypes := []gopacket.LayerType{}

	err := parser.DecodeLayers((*packet).Data(), &layerTypes)
	if err != nil {
		return
	}

	for _, layerType := range layerTypes {
		switch layerType {
		case layers.LayerTypeIPv4:
			SrcIP = ip4Layer.SrcIP.String()
			DstIP = ip4Layer.DstIP.String()
		case layers.LayerTypeIPv6:
			SrcIP = ip6Layer.SrcIP.String()
			DstIP = ip6Layer.DstIP.String()
		case layers.LayerTypeUDP:
			SrcPort = uint16(udpLayer.SrcPort)
			DstPort = uint16(udpLayer.DstPort)
		case layers.LayerTypeDNS:
			if dnsLayer.QR {
				//fmt.Printf("Answers: %+v\n", dnsLayer.Answers)
				//fmt.Printf("Question: %s\n", dnsLayer.Questions[0])

				timestamp := time.Now().Format(time.RFC3339)
				d := DnsMsg{
					Timestamp:       timestamp,
					SourceIP:        SrcIP,
					DestinationIP:   DstIP,
					SourcePort:      SrcPort,
					DestinationPort: DstPort,
					ResponseCode:    dnsLayer.ResponseCode.String(),
					Opcode:          dnsLayer.OpCode.String(),
				}

				for _, question := range dnsLayer.Questions {
					dq := DnsQuestion{
						Type:  question.Type.String(),
						Class: question.Class.String(),
						Name:  string(question.Name),
					}
					d.Query = append(d.Query, dq)
				}

				for _, answer := range dnsLayer.Answers {
					da := DnsAnswer{
						Type:  answer.Type.String(),
						Class: answer.Class.String(),
						TTL:   answer.TTL,
					}

					switch da.Type {
					case "A":
						da.Value = answer.IP.String()
						break
					case "AAAA":
						da.Value = answer.IP.String()
						break
					case "MX":
						da.Value = string(answer.MX.Name)
						break
					case "CNAME":
						da.Value = string(answer.CNAME)
						break
					case "PTR":
						da.Value = string(answer.PTR)
						break
					case "NS":
						da.Value = string(answer.NS)
						break
					case "TXT":
						for _, entry := range answer.TXTs {
							da.Value = fmt.Sprintf("%s\n%s", da.Value, string(entry))
						}
						da.Value = strings.Trim(da.Value, "\n")
						break
					}

					d.Answer = append(d.Answer, da)
				}

				if stdout {
					log.Printf("%+v", d)
				}
				if prefix != "" || mongoURI != "" {
					outputHandle.Write(&d)
				}
			}
		}
	}
}
