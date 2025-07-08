package internal

import (
	"context"
	"os"
	"path/filepath"

	l "github.com/ricardomolendijk/loggerz"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func GetKubeConfig() *rest.Config {
	config, err := rest.InClusterConfig()
	if err == nil {
		l.Info("Loaded in-cluster kube config")
		return config
	}
	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "dev.yaml")
	config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		l.Fatal("Failed to load kube config", "error", err)
	}
	l.Info("Loaded local kube config")
	return config
}

func GetClusterName(clientset *kubernetes.Clientset, cfgCluster string) string {
	nodes, err := clientset.CoreV1().Nodes().List(
		context.TODO(),
		metav1.ListOptions{},
	)
	if err == nil {
		for _, node := range nodes.Items {
			for _, key := range []string{
				"cluster-name",
				"kubernetes.azure.com/cluster",
				"eks.amazonaws.com/cluster-name",
			} {
				if val, ok := node.Labels[key]; ok {
					l.Info("Detected cluster name from node label", "cluster", val)
					return val
				}
			}
		}
	} else {
		l.Debug("Could not get cluster name from node labels", "error", err)
	}
	kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "dev.yaml")
	config, err := clientcmd.LoadFromFile(kubeconfig)
	if err == nil && config.CurrentContext != "" {
		ctx := config.Contexts[config.CurrentContext]
		if ctx != nil && ctx.Cluster != "" {
			l.Info("Detected cluster name from kubeconfig", "cluster", ctx.Cluster)
			return ctx.Cluster
		}
	} else {
		l.Debug("Could not get cluster name from kubeconfig", "error", err)
	}
	if cfgCluster != "" {
		l.Info("Using cluster name from config", "cluster", cfgCluster)
		return cfgCluster
	}
	return "unknown-cluster"
}
