package internal

import (
	"encoding/json"
	"io/ioutil"
	"os"

	l "github.com/ricardomolendijk/loggerz"
)

type Config struct {
	MongoURI  string `json:"mongo_uri"`
	MongoDB   string `json:"mongo_db"`
	Cluster   string `json:"cluster"`
	LogLevel  string `json:"log_level"`
	LogDir    string `json:"log_dir"`
	SaveLogs  *bool  `json:"save_logs"`
}

func LoadConfig() Config {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "./config.local.json"
	}
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		l.Fatal("Failed to read config", "error", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		l.Fatal("Failed to parse config", "error", err)
	}
	if cfg.LogDir == "" {
		cfg.LogDir = "./logs"
	}
	if cfg.SaveLogs == nil {
		b := true
		cfg.SaveLogs = &b
	}
	return cfg
}
