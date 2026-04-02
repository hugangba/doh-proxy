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