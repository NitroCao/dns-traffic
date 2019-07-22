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
	"context"
	"encoding/json"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"os"
	"sync"
	"time"
)

type output interface {
	Init(target string)
	Write(v *DnsMsg)
}

type jsonFile struct {
	file  *os.File
	mutex sync.Mutex
}

func (j *jsonFile) Init(prefix string) {
	t := time.Now()
	filename := prefix + "." + t.Format(dateLayout)
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		log.Printf("[ERROR]: Failed to open file %s: %s", filename, err.Error())
		os.Exit(1)
	}
	log.Printf("[INFO]: Output Mode: jsonFile")
	log.Printf("[INFO]: Opened file %s", filename)

	j.file = file
}

func (j *jsonFile) Write(v *DnsMsg) {
	data, err := json.Marshal(v)
	if err != nil {
		log.Printf("[ERROR]: Failed to marshal data: %s", err.Error())
		return
	}
	data = append(data, '\n')

	j.mutex.Lock()
	defer j.mutex.Unlock()
	numWrite, err := j.file.Write(data)
	if err != nil {
		log.Printf("[ERROR]: Failed to write data into file: %s", err.Error())
		return
	}

	if numWrite != len(data) {
		log.Printf("[ERROR]: Write bytes didn't equal to the length of original data")
	}
}

type mongoDB struct {
	url        string
	client     *mongo.Client
	collection *mongo.Collection
}

func (m *mongoDB) Init(url string) {
	ctx, _ := context.WithTimeout(context.Background(), dbTimeout)
	m.client, err = mongo.Connect(ctx, options.Client().ApplyURI(mongoURI))
	if err != nil {
		log.Fatalf("[ERROR]: Failed to make a new mongoDB client: %s", err.Error())
	}
	log.Printf("[INFO]: OutputMode: MongoDB")
	log.Printf("[INFO]: Connected to the database.")

	m.collection = m.client.Database(dbName).Collection(dbCollection)
}

func (m *mongoDB) Write(v *DnsMsg) {
	if _, err = m.collection.InsertOne(context.Background(), v); err != nil {
		log.Fatalf("[ERROR]: Failed to write data into MongoDB: %s", err.Error())
	}
}
