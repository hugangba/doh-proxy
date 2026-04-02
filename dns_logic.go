package main

import (
	"encoding/json"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
)

type DoHJSONResponse struct {
	Status int `json:"Status"`
	Answer []struct {
		Name string `json:"name"`
		Type int    `json:"type"`
		Data string `json:"data"`
	} `json:"Answer"`
}

func handleDnsQuery(rawBuffer []byte, config Config) ([]byte, error) {
	id, qName, qType, err := parseDnsPacket(rawBuffer)
	if err != nil || qName == "" {
		return forwardAndRead(rawBuffer)
	}

	qName = strings.ToLower(strings.TrimSuffix(qName, "."))

	// 1. 远程自定义解析优先
	remoteConfigMutex.RLock()
	custom, exists := remoteConfig.Domains[qName]
	remoteConfigMutex.RUnlock()

	if exists {
		// 处理 IPv4 (A 记录)
		if qType == 1 && len(custom.IP4) > 0 {
			var ips [][]byte
			for _, ip := range custom.IP4 {
				if b := ipToBytes(ip); b != nil { ips = append(ips, b) }
			}
			return createMultiAnsResponse(id, qName, 1, ips, 300), nil
		}
		// 处理 IPv6 (AAAA 记录) - 之前漏掉了这里
		if qType == 28 && len(custom.IP6) > 0 {
			var ips [][]byte
			for _, ip := range custom.IP6 {
				if b := ipToBytes(ip); b != nil { ips = append(ips, b) }
			}
			return createMultiAnsResponse(id, qName, 28, ips, 300), nil
		}
		// 处理 ECH (HTTPS 记录)
		if qType == 65 && custom.ECH != "" {
			echRdata := packHttpsParams(1, ".", []SvcParam{
				{Key: "alpn", Val: "h2,h3"},
				{Key: "ech", Val: custom.ECH},
			})
			return createMultiAnsResponse(id, qName, 65, [][]byte{echRdata}, 300), nil
		}
	}

	// 2. 虚拟域名逻辑
	if qName == "cf.ech" || qName == "fb.ech" {
		if qType == 65 {
			randomTtl := uint32(rand.Intn(10800-7200+1) + 7200)
			if qName == "cf.ech" {
				echRdata := fetchCleanEchRdata(config.EchDomain)
				if echRdata != nil {
					return createMultiAnsResponse(id, qName, 65, [][]byte{echRdata}, randomTtl), nil
				}
			} else {
				echRdata := packHttpsParams(1, ".", []SvcParam{
					{Key: "alpn", Val: "h2,h3"},
					{Key: "ech", Val: META_ECH_CONFIG},
				})
				return createMultiAnsResponse(id, qName, 65, [][]byte{echRdata}, randomTtl), nil
			}
		}
		return createMultiAnsResponse(id, qName, qType, nil, 3600), nil
	}

	// 3. Twitter 劫持逻辑
	isTwitter := false
	for _, d := range TWITTER_DOMAINS {
		if qName == d || strings.HasSuffix(qName, "."+d) {
			isTwitter = true
			break
		}
	}
	if isTwitter {
		if qType == 1 {
			var replaceIps [][]byte
			if config.Ip4 != "" {
				for _, ip := range strings.Split(config.Ip4, ",") {
					if b := ipToBytes(ip); b != nil { replaceIps = append(replaceIps, b) }
				}
			} else {
				replaceIps = [][]byte{ipToBytes(DEFAULT_TWITTER_IP)}
			}
			return createMultiAnsResponse(id, qName, 1, replaceIps, 300), nil
		}
	}

	// 4. 自动探测逻辑 (Meta/CF)
	ownerData := getOwnerFromCache(qName)
	var probedIps []string
	if ownerData == "" {
		ownerData, probedIps = activeProbeOwner(qName)
	}

	if (qType == 1 || qType == 28) && ownerData == "META" {
		var rawIps [][]byte
		// 如果有探测到的 IP 则使用，否则转发获取
		if len(probedIps) > 0 {
			for _, ip := range probedIps {
				isV6 := strings.Contains(ip, ":")
				if (qType == 1 && !isV6) || (qType == 28 && isV6) {
					if b := ipToBytes(ip); b != nil { rawIps = append(rawIps, b) }
				}
			}
		}
		if len(rawIps) > 0 {
			return createMultiAnsResponse(id, qName, qType, rawIps, 300), nil
		}
	}

	if qType == 65 && ownerData == "META" {
		echRdata := packHttpsParams(1, ".", []SvcParam{
			{Key: "alpn", Val: "h2,h3"},
			{Key: "ech", Val: META_ECH_CONFIG},
		})
		return createMultiAnsResponse(id, qName, 65, [][]byte{echRdata}, 300), nil
	}

	return forwardAndRead(rawBuffer)
}

func activeProbeOwner(domain string) (string, []string) {
	req, _ := http.NewRequest("GET", UPSTREAM_JSON+"?name="+domain+"&type=1", nil)
	req.Header.Set("Accept", "application/dns-json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 { return "", nil }
	defer resp.Body.Close()
	var data DoHJSONResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil { return "", nil }

	var ips []string
	var detectedOwner string
	for _, a := range data.Answer {
		if a.Type == 1 {
			ips = append(ips, a.Data)
			if detectedOwner == "" {
				if isIpInCompiledCidrs(a.Data, compiledMeta) { detectedOwner = "META"
				} else if isIpInCompiledCidrs(a.Data, compiledCF) { detectedOwner = "CF" }
			}
		}
	}
	if detectedOwner != "" { setOwnerCache(domain, detectedOwner) }
	return detectedOwner, ips
}

// 补全 ECH 获取逻辑
func fetchCleanEchRdata(domain string) []byte {
	req, _ := http.NewRequest("GET", UPSTREAM_JSON+"?name="+domain+"&type=65", nil)
	req.Header.Set("Accept", "application/dns-json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 { return nil }
	defer resp.Body.Close()

	var data DoHJSONResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil { return nil }

	if data.Status == 0 {
		for _, a := range data.Answer {
			if a.Type == 65 {
				if strings.HasPrefix(a.Data, "\\#") { continue }
				parts := strings.Fields(a.Data)
				if len(parts) < 3 { continue }
				
				priority, _ := strconv.Atoi(parts[0])
				target := parts[1]
				var params []SvcParam
				for i := 2; i < len(parts); i++ {
					if strings.Contains(parts[i], "=") {
						kv := strings.SplitN(parts[i], "=", 2)
						if kv[0] == "alpn" || kv[0] == "ech" {
							params = append(params, SvcParam{Key: kv[0], Val: kv[1]})
						}
					}
				}
				return packHttpsParams(uint16(priority), target, params)
			}
		}
	}
	return nil
}