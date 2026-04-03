package main

import (
	"sync"
	"time"
)

type CacheItem struct {
	Val    interface{}
	Expire int64
}

var globalCache sync.Map

func getOwnerFromCache(name string) string {
	if val, ok := globalCache.Load("owner:" + name); ok {
		item := val.(CacheItem)
		if time.Now().UnixMilli() < item.Expire {
			return item.Val.(string)
		}
		globalCache.Delete("owner:" + name)
	}
	return ""
}

func setOwnerCache(name, owner string) {
	globalCache.Store("owner:"+name, CacheItem{
		Val:    owner,
		Expire: time.Now().UnixMilli() + 3600*1000,
	})
}

func getEchFromCache(domain string) []byte {
	if val, ok := globalCache.Load("ech:" + domain); ok {
		item := val.(CacheItem)
		if time.Now().UnixMilli() < item.Expire {
			return item.Val.([]byte)
		}
		globalCache.Delete("ech:" + domain)
	}
	return nil
}

func setEchCache(domain string, data []byte) {
	globalCache.Store("ech:"+domain, CacheItem{
		Val:    data,
		Expire: time.Now().UnixMilli() + 3600*1000,
	})
}
