package internal

import (
	"context"
	"sync"
	"time"

	l "github.com/ricardomolendijk/loggerz"
	"go.mongodb.org/mongo-driver/mongo"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

func WatchResource(db *mongo.Database, dynClient dynamic.Interface, resourceType, clusterName string, wg *sync.WaitGroup) {
	defer wg.Done()
	group := "aquasecurity.github.io"
	version := "v1alpha1"
	plural := resourceType
	gvr := schema.GroupVersionResource{Group: group, Version: version, Resource: plural}
	for {
		watcher, err := dynClient.Resource(gvr).Watch(context.TODO(), metav1.ListOptions{})
		if err != nil {
			l.Error("Error watching resource", "resourceType", resourceType, "error", err)
			time.Sleep(5 * time.Second)
			continue
		}
		for event := range watcher.ResultChan() {
			obj, ok := event.Object.(*unstructured.Unstructured)
			if !ok {
				continue
			}
			SyncToMongo(db, resourceType, clusterName, obj.Object, string(event.Type))
		}
	}
}

func WatchNamespaces(db *mongo.Database, clientset *kubernetes.Clientset, clusterName string, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		watcher, err := clientset.CoreV1().Namespaces().Watch(context.TODO(), metav1.ListOptions{})
		if err != nil {
			l.Error("Error watching namespaces", "error", err)
			time.Sleep(5 * time.Second)
			continue
		}
		for event := range watcher.ResultChan() {
			ns, ok := event.Object.(*corev1.Namespace)
			if !ok {
				continue
			}
			nsMap := namespaceToMap(*ns)
			SyncNamespaceToMongo(db, clusterName, nsMap, string(event.Type))
		}
	}
}
