package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

type CustomResolution struct {
	IP4 []string `json:"ip4,omitempty"`
	IP6 []string `json:"ip6,omitempty"`
	ECH string   `json:"ech,omitempty"`
}

type RemoteConfig struct {
	Domains map[string]CustomResolution `json:"domains"`
}

var (
	remoteConfig      RemoteConfig
	remoteConfigMutex sync.RWMutex
)

func startRemoteConfigUpdater(url string) {
	go func() {
		for {
			// 先睡眠，因为启动时已经同步获取过一次了
			time.Sleep(10 * time.Minute)
			updateRemoteConfig(url)
		}
	}()
}

func updateRemoteConfig(url string) {
	client := http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		log.Printf("Remote config fetch failed: %v", err)
		return
	}
	defer resp.Body.Close()

	var newConfig RemoteConfig
	if err := json.NewDecoder(resp.Body).Decode(&newConfig); err != nil {
		log.Printf("Remote config parse failed: %v", err)
		return
	}

	remoteConfigMutex.Lock()
	remoteConfig = newConfig
	remoteConfigMutex.Unlock()
	log.Printf("Remote config updated: %d domains loaded", len(newConfig.Domains))
}
