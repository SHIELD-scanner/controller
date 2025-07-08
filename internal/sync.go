package internal

import (
	"context"

	l "github.com/ricardomolendijk/loggerz"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

func SyncToMongo(db *mongo.Database, resourceType, clusterName string, obj map[string]interface{}, eventType string) {
	meta, _ := obj["metadata"].(map[string]interface{})
	uid, _ := meta["uid"].(string)
	if uid == "" {
		l.Warn("No UID for resource", "resourceType", resourceType, "name", meta["name"])
		return
	}
	doc := bson.M{
		"_uid":          uid,
		"_event_type":   eventType,
		"_resource_type": resourceType,
		"_namespace":    meta["namespace"],
		"_name":         meta["name"],
		"_cluster":      clusterName,
		"data":          obj,
	}
	_, err := db.Collection(resourceType).ReplaceOne(context.TODO(), bson.M{"_uid": uid}, doc, options.Replace().SetUpsert(true))
	if err != nil {
		l.Error("Failed to sync resource", "resourceType", resourceType, "name", meta["name"], "error", err)
	} else {
		l.Info("Synced resource", "resourceType", resourceType, "name", meta["name"], "eventType", eventType)
	}
}

func InitialImportResource(db *mongo.Database, dynClient dynamic.Interface, resourceType, clusterName string) {
	group := "aquasecurity.github.io"
	version := "v1alpha1"
	plural := resourceType
	gvr := schema.GroupVersionResource{Group: group, Version: version, Resource: plural}
	objs, err := dynClient.Resource(gvr).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		l.Error("Error during initial import", "resourceType", resourceType, "error", err)
		return
	}
	l.Info("Initial import", "resourceType", resourceType, "count", len(objs.Items))
	currentUIDs := make(map[string]struct{})
	for _, obj := range objs.Items {
		uid, _, _ := unstructured.NestedString(obj.Object, "metadata", "uid")
		if uid != "" {
			currentUIDs[uid] = struct{}{}
		}
		SyncToMongo(db, resourceType, clusterName, obj.Object, "INITIAL_IMPORT")
	}
	var uids []string
	for uid := range currentUIDs {
		uids = append(uids, uid)
	}
	_, err = db.Collection(resourceType).DeleteMany(context.TODO(), bson.M{"_uid": bson.M{"$nin": uids}})
	if err != nil {
		l.Error("Failed to remove stale records", "resourceType", resourceType, "error", err)
	}
}
