package internal

import (
	"context"

	l "github.com/ricardomolendijk/loggerz"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func ConnectMongo(uri, dbName string) *mongo.Database {
	client, err := mongo.Connect(context.TODO(), options.Client().ApplyURI(uri))
	if err != nil {
		l.Fatal("Failed to connect to MongoDB", "error", err)
	}
	return client.Database(dbName)
}
