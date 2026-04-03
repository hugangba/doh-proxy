package main

import (
	"io"
	"log"
	"net/http"
	"os"
)

func main() {
	// 初始化 CIDR 编译
	initCompiledCidrs()

	// 启动远程配置更新协程
	remoteUrl := os.Getenv("REMOTE_CONFIG_URL")
	if remoteUrl != "" {
		log.Printf("Remote config enabled: %s", remoteUrl)
		// 首次同步获取，确保启动时配置已加载，防止启动瞬间的 DNS 泄漏
		updateRemoteConfig(remoteUrl)
		startRemoteConfigUpdater(remoteUrl)
	}

	http.HandleFunc("/", handler)
	
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Server listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// 处理 /doh-ech-proxy 逻辑
	if r.URL.Path == API_PATH {
		config := Config{
			Ip4:       r.URL.Query().Get("ip4"),
			Ip6:       r.URL.Query().Get("ip6"),
			CfDomain:  r.URL.Query().Get("cf"),
			EchDomain: r.URL.Query().Get("ech"),
		}
		if config.EchDomain == "" {
			config.EchDomain = "cloudflare-ech.com"
		}

		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			res, err := handleDnsQuery(body, config)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.Header().Set("Content-Type", "application/dns-message")
			w.Write(res)
			return
		}

		if r.Method == "GET" && r.URL.Query().Get("dns") != "" {
			dnsQuery := decodeBase64UrlSafe(r.URL.Query().Get("dns"))
			if dnsQuery != nil {
				res, err := handleDnsQuery(dnsQuery, config)
				if err == nil {
					w.Header().Set("Content-Type", "application/dns-message")
					w.Write(res)
					return
				}
			}
		}
		w.WriteHeader(200)
		w.Write([]byte("OK"))
		return
	}

	// 处理 /doh-proxy 逻辑
	if r.URL.Path == TEST_PATH {
		if r.Method == "POST" {
			body, _ := io.ReadAll(r.Body)
			res, err := forwardAndRead(body)
			if err == nil {
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(res)
				return
			}
		}

		if r.Method == "GET" && r.URL.Query().Get("dns") != "" {
			dnsQuery := decodeBase64UrlSafe(r.URL.Query().Get("dns"))
			if dnsQuery != nil {
				res, err := forwardAndRead(dnsQuery)
				if err == nil {
					w.Header().Set("Content-Type", "application/dns-message")
					w.Write(res)
					return
				}
			}
		}
		w.WriteHeader(200)
		w.Write([]byte("OK"))
		return
	}

	http.NotFound(w, r)
}
