package intelligence

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

// SEC-FIX VULN-005: Límite máximo de lectura para respuestas JSON de EPSS (5MB)
const maxEpssResponseBytes = 5 * 1024 * 1024

type EpssResponse struct {
	Status  string `json:"status"`
	Type    string `json:"type"`
	Version string `json:"version"`
	Access  string `json:"access"`
	Total   int    `json:"total"`
	Data    []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

var (
	epssCacheLock sync.RWMutex
	epssCache     = make(map[string]EpssData)
)

type EpssData struct {
	Score      float64
	Percentile float64
}

func FetchEPSS(cve string) (EpssData, error) {
	epssCacheLock.RLock()
	data, ok := epssCache[cve]
	epssCacheLock.RUnlock()
	if ok {
		return data, nil
	}

	// SEC-FIX VULN-001: Cliente HTTP con TLS 1.2 mínimo y límite de redirecciones
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("demasiadas redirecciones HTTP (máx. 3)")
			}
			return nil
		},
	}

	url := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", cve)

	// SEC-FIX VULN-009: Usar context.WithTimeout para control granular del timeout
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return EpssData{}, err
	}
	// SEC-FIX VULN-006: User-Agent genérico
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SecurityAuditor/1.0)")

	httpResp, err := client.Do(req)
	if err != nil {
		return EpssData{}, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return EpssData{}, fmt.Errorf("EPSS API error: %d", httpResp.StatusCode)
	}

	// SEC-FIX VULN-005: Decodificar JSON con lectura limitada para evitar Memory Exhaustion
	var res EpssResponse
	decoder := json.NewDecoder(io.LimitReader(httpResp.Body, maxEpssResponseBytes))
	if err := decoder.Decode(&res); err != nil {
		return EpssData{}, err
	}

	if len(res.Data) > 0 {
		var score, perc float64
		fmt.Sscanf(res.Data[0].EPSS, "%f", &score)
		fmt.Sscanf(res.Data[0].Percentile, "%f", &perc)
		
		data := EpssData{Score: score, Percentile: perc}
		
		epssCacheLock.Lock()
		epssCache[cve] = data
		epssCacheLock.Unlock()
		
		return data, nil
	}

	return EpssData{}, fmt.Errorf("no EPSS data for %s", cve)
}
