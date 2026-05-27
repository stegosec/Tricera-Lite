package intelligence

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const cisaURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// SEC-FIX VULN-005: Límite máximo de lectura para respuestas JSON de CISA (50MB)
const maxCisaResponseBytes = 50 * 1024 * 1024

type CisaCatalog struct {
	Vulnerabilities []CisaKevEntry `json:"vulnerabilities"`
}

var (
	kevCacheLock    sync.RWMutex
	globalKevCache  map[string]CisaKevEntry
	// SEC-FIX VULN-012: TTL del cache KEV para invalidar datos antiguos
	kevCacheTime    time.Time
	kevCacheTTL     = 30 * time.Minute
)

// SEC-FIX VULN-001: Cliente HTTP seguro con TLS 1.2 mínimo y límite de redirecciones
func newSecureHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("demasiadas redirecciones HTTP (máx. 3)")
			}
			return nil
		},
	}
}

func FetchCisaKev() (map[string]bool, error) {
	kevMap := make(map[string]bool)
	
	client := newSecureHTTPClient(15 * time.Second)
	
	req, err := http.NewRequest("GET", cisaURL, nil)
	if err != nil {
		return kevMap, err
	}
	// SEC-FIX VULN-006: User-Agent genérico
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityAuditor/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return kevMap, err
	}
	defer resp.Body.Close()

	// SEC-FIX VULN-005: Decodificar JSON con lectura limitada para evitar Memory Exhaustion
	var catalog CisaCatalog
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxCisaResponseBytes))
	if err := decoder.Decode(&catalog); err != nil {
		return kevMap, err
	}

	kevCacheLock.Lock()
	globalKevCache = make(map[string]CisaKevEntry)
	for _, v := range catalog.Vulnerabilities {
		kevMap[v.CVEID] = true
		globalKevCache[v.CVEID] = v
	}
	// SEC-FIX VULN-012: Registrar timestamp del cache para permitir invalidación por TTL
	kevCacheTime = time.Now()
	kevCacheLock.Unlock()
	
	return kevMap, nil
}

func FetchCisaKevByCVE(cve string) (CisaKevEntry, bool) {
	// SEC-FIX VULN-012: Verificar si el cache ha expirado y refrescarlo si es necesario
	kevCacheLock.RLock()
	cacheExpired := globalKevCache == nil || time.Since(kevCacheTime) > kevCacheTTL
	kevCacheLock.RUnlock()

	if cacheExpired {
		_, _ = FetchCisaKev()
	}

	kevCacheLock.RLock()
	defer kevCacheLock.RUnlock()
	
	if globalKevCache == nil {
		return CisaKevEntry{}, false
	}
	entry, ok := globalKevCache[cve]
	return entry, ok
}
