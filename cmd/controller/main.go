package main

import (
	"sync"

	l "github.com/ricardomolendijk/loggerz"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"controller/internal"
)

var aquaResources = []string{
	"vulnerabilityreports",
	"clustercompliancereports",
	"clusterconfigauditreports",
	"clusterinfraassessmentreports",
	"clusterrbacassessmentreports",
	"clustersbomreports",
	"clustervulnerabilityreports",
	"configauditreports",
	"exposedsecretreports",
	"infraassessmentreports",
	"rbacassessmentreports",
	"sbomreports",
}

func main() {
	cfg := internal.LoadConfig()
	internal.SetupLogger(cfg.LogLevel, cfg.LogDir, *cfg.SaveLogs)
	kubeConfig := internal.GetKubeConfig()
	clientset, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		l.Fatal("Failed to create Kubernetes client", "error", err)
	}
	dynClient, err := dynamic.NewForConfig(kubeConfig)
	if err != nil {
		l.Fatal("Failed to create dynamic client", "error", err)
	}
	db := internal.ConnectMongo(cfg.MongoURI, cfg.MongoDB)
	clusterName := internal.GetClusterName(clientset, cfg.Cluster)

	for _, res := range aquaResources {
		internal.InitialImportResource(db, dynClient, res, clusterName)
	}
	internal.InitialImportNamespaces(db, clientset, clusterName)

	var wg sync.WaitGroup
	for _, res := range aquaResources {
		wg.Add(1)
		go internal.WatchResource(db, dynClient, res, clusterName, &wg)
	}
	wg.Add(1)
	go internal.WatchNamespaces(db, clientset, clusterName, &wg)
	l.Info("Controller started. Watching resources and namespaces...")
	wg.Wait()
}
