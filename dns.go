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

type DnsMsg struct {
	Timestamp       string `json:"timestamp"`
	SourceIP        string
	DestinationIP   string
	SourcePort      uint16 `json:"int"`
	DestinationPort uint16 `json:"int"`
	Query           []DnsQuestion
	Answer          []DnsAnswer
	ResponseCode    string
	Opcode          string
}

type DnsQuestion struct {
	Type  string
	Class string
	Name  string
}

type DnsAnswer struct {
	Type  string
	Class string
	TTL   uint32 `json:"ing"`
	Value string
}
