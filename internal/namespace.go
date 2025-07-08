package internal

import (
	"context"
	"encoding/json"

	l "github.com/ricardomolendijk/loggerz"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

func SyncNamespaceToMongo(db *mongo.Database, clusterName string, obj map[string]interface{}, eventType string) {
	meta, _ := obj["metadata"].(map[string]interface{})
	uid, _ := meta["uid"].(string)
	if uid == "" {
		l.Warn("No UID for namespace", "name", meta["name"])
		return
	}
	doc := bson.M{
		"_uid":         uid,
		"_event_type":  eventType,
		"_resource_type": "namespace",
		"_name":        meta["name"],
		"_cluster":     clusterName,
		"data":         obj,
	}
	_, err := db.Collection("namespaces").ReplaceOne(context.TODO(), bson.M{"_uid": uid}, doc, options.Replace().SetUpsert(true))
	if err != nil {
		l.Error("Failed to sync namespace", "name", meta["name"], "error", err)
	} else {
		l.Info("Synced namespace", "name", meta["name"], "eventType", eventType)
	}
}

func namespaceToMap(ns corev1.Namespace) map[string]interface{} {
	b, _ := json.Marshal(ns)
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	return m
}

func InitialImportNamespaces(db *mongo.Database, clientset *kubernetes.Clientset, clusterName string) {
	nsList, err := clientset.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		l.Error("Error during initial import of namespaces", "error", err)
		return
	}
	l.Info("Initial import", "resourceType", "namespaces", "count", len(nsList.Items))
	currentUIDs := make(map[string]struct{})
	for _, ns := range nsList.Items {
		nsMap := namespaceToMap(ns)
		meta, _ := nsMap["metadata"].(map[string]interface{})
		uid, _ := meta["uid"].(string)
		if uid != "" {
			currentUIDs[uid] = struct{}{}
		}
		SyncNamespaceToMongo(db, clusterName, nsMap, "INITIAL_IMPORT")
	}
	var uids []string
	for uid := range currentUIDs {
		uids = append(uids, uid)
	}
	_, err = db.Collection("namespaces").DeleteMany(context.TODO(), bson.M{"_uid": bson.M{"$nin": uids}})
	if err != nil {
		l.Error("Failed to remove stale namespaces", "error", err)
	}
}
