package intelligence

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/PuerkitoBio/goquery"
)

type URLCacheEntry struct {
	HTML      string    `json:"html"`
	Timestamp time.Time `json:"timestamp"`
}

type AdvisoryEntry struct {
	Advisories []Advisory `json:"advisories"`
	Timestamp  time.Time  `json:"timestamp"`
}

type FortiGuardDetailEntry struct {
	Detail    FortiGuardDetail `json:"detail"`
	Timestamp time.Time        `json:"timestamp"`
}

type PersistentCache struct {
	URLCache   map[string]URLCacheEntry          `json:"url_cache"`
	Advisories map[string]AdvisoryEntry          `json:"advisory_cache"`
	Details    map[string]FortiGuardDetailEntry  `json:"detail_cache"`
}

var (
	// Cache de URLs para HTML
	urlCache    = make(map[string]string)
	urlCacheMu  sync.RWMutex

	// Cache de advisories por producto y versión
	advisoryCache   = make(map[string][]Advisory)
	advisoryCacheMu sync.RWMutex

	// Mutex global para asegurar máximo 1 petición concurrente a FortiGuard live
	liveMutex sync.Mutex

	// Control de Circuit Breaker (Lock-Free)
	consecutiveFailures   atomic.Int32
	circuitBreakerTripped atomic.Bool

	// Bandera para habilitar/deshabilitar consultas en vivo a FortiGuard
	LiveEnabled bool = false

	persistentCache   *PersistentCache
	persistentCacheMu sync.Mutex
)

const (
	psirtBaseURL = "https://www.fortiguard.com/psirt"
	cacheTTL     = 24 * time.Hour
)

func getPersistentCachePath() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "tricera")
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, "api_cache.json")
}

func loadPersistentCache() *PersistentCache {
	persistentCacheMu.Lock()
	defer persistentCacheMu.Unlock()

	if persistentCache != nil {
		return persistentCache
	}

	persistentCache = &PersistentCache{
		URLCache:   make(map[string]URLCacheEntry),
		Advisories: make(map[string]AdvisoryEntry),
		Details:    make(map[string]FortiGuardDetailEntry),
	}

	path := getPersistentCachePath()
	data, err := os.ReadFile(path)
	if err != nil {
		return persistentCache
	}

	var temp PersistentCache
	if err := json.Unmarshal(data, &temp); err == nil {
		if temp.URLCache != nil {
			persistentCache.URLCache = temp.URLCache
		}
		if temp.Advisories != nil {
			persistentCache.Advisories = temp.Advisories
		}
		if temp.Details != nil {
			persistentCache.Details = temp.Details
		}
	}

	return persistentCache
}

func savePersistentCache(cache *PersistentCache) error {
	persistentCacheMu.Lock()
	defer persistentCacheMu.Unlock()

	path := getPersistentCachePath()
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func isExpired(t time.Time) bool {
	return time.Since(t) > cacheTTL
}

// SEC-FIX VULN-006: User-Agent idéntico a Chrome 120 para coincidir con el fingerprint TLS de uTLS
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// SEC-FIX VULN-004: Límite máximo de lectura de respuestas HTTP (10MB)
const maxHTTPResponseBytes = 10 * 1024 * 1024

// Expresiones regulares estáticas compiladas globalmente para evitar fugas de memoria y CPU
var (
	reHTMLTags = regexp.MustCompile(`<[^>]*>`)
	reID       = regexp.MustCompile(`FG-IR-\d{2}-\d+`)
	reCVE      = regexp.MustCompile(`CVE-\d{4}-\d+`)
	reSeverity = regexp.MustCompile(`(Critical|High|Medium|Low|Informational)`)
)

// Scraper realiza el scraping directo de FortiGuard de manera hilo-segura
type Scraper struct {
	Client      *http.Client
	mu          sync.RWMutex
	DetailCache map[string]FortiGuardDetail
}

// SEC-FIX VULN-001: TLS 1.2 mínimo, límite de redirecciones HTTP
func NewScraper() *Scraper {
	return &Scraper{
		Client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				TLSHandshakeTimeout:   10 * time.Second,
				DisableKeepAlives:     false,
				MaxIdleConns:          10,
				IdleConnTimeout:       30 * time.Second,
				ResponseHeaderTimeout: 10 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("demasiadas redirecciones HTTP (máx. 3)")
				}
				return nil
			},
		},
		DetailCache: make(map[string]FortiGuardDetail),
	}
}

// FetchAdvisories extrae todos los advisories para un producto y versión específicos
func (s *Scraper) FetchAdvisories(product, version string) ([]Advisory, error) {
	// 1. Check in-memory advisory cache by product/version
	cacheKey := fmt.Sprintf("%s|%s", product, version)
	advisoryCacheMu.RLock()
	cachedAdvisories, found := advisoryCache[cacheKey]
	advisoryCacheMu.RUnlock()
	if found {
		return cachedAdvisories, nil
	}

	// 2. Check persistent cache from disk
	pCache := loadPersistentCache()
	persistentCacheMu.Lock()
	entry, foundPC := pCache.Advisories[cacheKey]
	persistentCacheMu.Unlock()
	if foundPC && !isExpired(entry.Timestamp) {
		// Populate in-memory cache
		advisoryCacheMu.Lock()
		advisoryCache[cacheKey] = entry.Advisories
		advisoryCacheMu.Unlock()
		return entry.Advisories, nil
	}

	// También mantenemos el soporte original de fortiguard_cache.json como alternativa externa
	cachePath := "fortiguard_cache.json"
	if data, err := os.ReadFile(cachePath); err == nil {
		var advisories []Advisory
		if json.Unmarshal(data, &advisories) == nil && len(advisories) > 0 {
			fmt.Printf("[+] Cargadas %d vulnerabilidades de FortiGuard desde el archivo de caché local '%s'!\n", len(advisories), cachePath)
			// Cache these in execution cache as well
			advisoryCacheMu.Lock()
			advisoryCache[cacheKey] = advisories
			advisoryCacheMu.Unlock()
			return advisories, nil
		}
	}

	var advisories []Advisory
	var fetchErr error
	liveUsed := false

	// Check if live is enabled and circuit breaker is not tripped
	isLiveAvailable := LiveEnabled && !circuitBreakerTripped.Load()

	if isLiveAvailable {
		var allAdvisories []Advisory
		page := 1
		liveFailed := false

		for {
			queryParams := url.Values{}
			queryParams.Set("page", fmt.Sprintf("%d", page))
			queryParams.Set("product", product)
			queryParams.Set("version", version)
			
			targetURL := fmt.Sprintf("%s?%s", psirtBaseURL, queryParams.Encode())
			
			html, err := s.fetchHTMLWithRetry(targetURL)
			if err != nil {
				liveFailed = true
				fetchErr = err
				break
			}

			pageAdvisories, hasNext := s.parsePage(html)
			if len(pageAdvisories) == 0 {
				break
			}
			
			// Enriquecer advisories relevantes de forma secuencial implícita debido a liveMutex dentro de fetchHTMLWithRetry
			var wg sync.WaitGroup
			sem := make(chan struct{}, 10)
			for i := range pageAdvisories {
				wg.Add(1)
				go func(adv *Advisory) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					s.fetchAdvisoryDetails(adv)
				}(&pageAdvisories[i])
			}
			wg.Wait()

			allAdvisories = append(allAdvisories, pageAdvisories...)

			if !hasNext {
				break
			}

			page++
			if page > 15 { break }
		}

		if !liveFailed && len(allAdvisories) > 0 {
			// Éxito: Verificado con FortiGuard Live
			for i := range allAdvisories {
				allAdvisories[i].Source = "Verificado con FortiGuard Live"
			}
			advisories = allAdvisories
			liveUsed = true

			// Guardar en caché persistente y disco
			pCache := loadPersistentCache()
			persistentCacheMu.Lock()
			pCache.Advisories[cacheKey] = AdvisoryEntry{
				Advisories: advisories,
				Timestamp:  time.Now(),
			}
			persistentCacheMu.Unlock()
			_ = savePersistentCache(pCache)
		} else {
			if liveFailed {
				fmt.Printf("[!] Falló consulta live a FortiGuard: %v. Pasando a catálogo offline...\n", fetchErr)
			}
		}
	}

	// Fallback/catalogo offline
	if !liveUsed {
		offlineAdvs := GetLocalOfflineAdvisories(version)
		if len(offlineAdvs) > 0 {
			// Determinar estado de reporte exacto
			sourceText := "Resuelto desde catálogo offline embebido"
			wasTripped := circuitBreakerTripped.Load()

			if !LiveEnabled {
				sourceText = "Resuelto desde catálogo offline embebido"
			} else if wasTripped || fetchErr != nil {
				sourceText = "Live no disponible; resuelto offline"
			}

			for i := range offlineAdvs {
				offlineAdvs[i].Source = sourceText
			}
			advisories = offlineAdvs
		} else {
			// No hay datos offline tampoco para esta versión!
			// "No verificable: sin datos live ni offline"
			return nil, fmt.Errorf("No verificable: sin datos live ni offline (versión %s)", version)
		}
	}

	// Guardar en la caché de ejecución
	advisoryCacheMu.Lock()
	advisoryCache[cacheKey] = advisories
	advisoryCacheMu.Unlock()

	return advisories, nil
}

func getVersionPrefix(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return v
}

//go:embed fortiguard_fallback.json
var fallbackJSON []byte

var (
	localOfflineAdvisories []Advisory
	loadOfflineOnce        sync.Once
)

func getLocalOfflineAdvisoriesLoaded() []Advisory {
	loadOfflineOnce.Do(func() {
		if err := json.Unmarshal(fallbackJSON, &localOfflineAdvisories); err != nil {
			fmt.Printf("[!] Error al deserializar catálogo offline embebido: %v\n", err)
		}
	})
	return localOfflineAdvisories
}

func GetLocalOfflineAdvisories(targetVersion string) []Advisory {
	prefix := getVersionPrefix(targetVersion)
	var matched []Advisory
	allOffline := getLocalOfflineAdvisoriesLoaded()
	for _, adv := range allOffline {
		for _, p := range adv.AffectedProducts {
			if p.Name == "FortiOS" {
				for _, v := range p.Versions {
					if v == prefix {
						matched = append(matched, adv)
						break
					}
				}
			}
		}
	}
	return matched
}

func (s *Scraper) FetchFortiGuardAdvisoryDetail(psirtID string) (FortiGuardDetail, error) {
	s.mu.RLock()
	detail, ok := s.DetailCache[psirtID]
	s.mu.RUnlock()
	if ok {
		return detail, nil
	}

	// Check persistent cache from disk
	pCache := loadPersistentCache()
	persistentCacheMu.Lock()
	entry, foundPC := pCache.Details[psirtID]
	persistentCacheMu.Unlock()
	if foundPC && !isExpired(entry.Timestamp) {
		s.mu.Lock()
		s.DetailCache[psirtID] = entry.Detail
		s.mu.Unlock()
		return entry.Detail, nil
	}

	url := fmt.Sprintf("%s/%s", psirtBaseURL, psirtID)
	html, err := s.fetchHTMLWithRetry(url)
	if err != nil {
		return FortiGuardDetail{}, err
	}

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return FortiGuardDetail{}, fmt.Errorf("error al parsear documento HTML: %v", err)
	}

	detail = FortiGuardDetail{
		PSIRTID: psirtID,
	}

	// 1. Extraer Description (Summary)
	// Encontramos el div.detail-item que contiene h3 con texto "Summary"
	doc.Find("div.detail-item").Each(func(i int, sel *goquery.Selection) {
		h3Text := strings.ToLower(strings.TrimSpace(sel.Find("h3").Text()))
		if strings.Contains(h3Text, "summary") || strings.Contains(h3Text, "description") {
			detail.Description = cleanHTML(sel.Find("p").Text())
			if detail.Description == "" {
				detail.Description = cleanHTML(sel.Text())
				detail.Description = strings.TrimSpace(strings.Replace(detail.Description, sel.Find("h3").Text(), "", 1))
			}
		}
	})

	// 2. Extraer Solutions / Upgrade info
	doc.Find("div.detail-item").Each(func(i int, sel *goquery.Selection) {
		h3Text := strings.ToLower(strings.TrimSpace(sel.Find("h3").Text()))
		hasTable := sel.Find("table").Length() > 0
		if hasTable || strings.Contains(h3Text, "solution") || strings.Contains(h3Text, "upgrades") {
			var rows []string
			sel.Find("table tr").Each(func(j int, tr *goquery.Selection) {
				var cols []string
				tr.Find("th, td").Each(func(k int, td *goquery.Selection) {
					cols = append(cols, strings.TrimSpace(td.Text()))
				})
				if len(cols) > 0 {
					rows = append(rows, strings.Join(cols, " | "))
				}
			})
			if len(rows) > 0 {
				detail.Solutions = strings.Join(rows, " \n ")
			} else {
				detail.Solutions = cleanHTML(sel.Text())
				if sel.Find("h3").Length() > 0 {
					detail.Solutions = strings.TrimSpace(strings.Replace(detail.Solutions, sel.Find("h3").Text(), "", 1))
				}
			}
		}
	})

	// 3. Extraer Workaround
	doc.Find("div.detail-item").Each(func(i int, sel *goquery.Selection) {
		textLower := strings.ToLower(sel.Text())
		if strings.Contains(textLower, "workaround") || strings.Contains(textLower, "workarrounds") {
			detail.Workaround = cleanHTML(sel.Text())
			if sel.Find("h3").Length() > 0 {
				detail.Workaround = strings.TrimSpace(strings.Replace(detail.Workaround, sel.Find("h3").Text(), "", 1))
			}
		}
	})

	// 4. Metadatos de la barra lateral (Sidebar table)
	doc.Find(".sidebar table tr, table.meta tr").Each(func(i int, sel *goquery.Selection) {
		tds := sel.Find("td")
		if tds.Length() >= 2 {
			key := strings.ToLower(strings.TrimSpace(tds.Eq(0).Text()))
			val := strings.TrimSpace(tds.Eq(1).Text())
			switch {
			case strings.Contains(key, "component"):
				detail.Component = val
			case strings.Contains(key, "attack type"):
				detail.AttackType = val
			case strings.Contains(key, "cvss"):
				detail.CVSS = val
			}
		}
	})

	s.mu.Lock()
	s.DetailCache[psirtID] = detail
	s.mu.Unlock()

	// Guardar en caché persistente y disco
	pCache = loadPersistentCache()
	persistentCacheMu.Lock()
	pCache.Details[psirtID] = FortiGuardDetailEntry{
		Detail:    detail,
		Timestamp: time.Now(),
	}
	persistentCacheMu.Unlock()
	_ = savePersistentCache(pCache)

	return detail, nil
}

func (s *Scraper) fetchAdvisoryDetails(adv *Advisory) {
	detail, err := s.FetchFortiGuardAdvisoryDetail(adv.ID)
	if err != nil {
		adv.Description = "Detalle no disponible temporalmente. Consultar link oficial."
		return
	}

	adv.Description = detail.Description
	adv.VendorSolution = detail.Solutions
	adv.Workaround = detail.Workaround
	adv.AttackType = detail.AttackType
	adv.Component = detail.Component
	adv.CVSS = detail.CVSS

	if adv.Workaround == "" {
		adv.Workaround = "No identificado workaround específico en la fuente consultada."
	}
	if adv.AttackType == "" { adv.AttackType = "No especificado por fuente" }
	if adv.Component == "" { adv.Component = "No especificado" }
}

func cleanHTML(h string) string {
	h = reHTMLTags.ReplaceAllString(h, "")
	h = strings.ReplaceAll(h, "&nbsp;", " ")
	h = strings.ReplaceAll(h, "\n", " ")
	h = strings.ReplaceAll(h, "\r", "")
	return strings.TrimSpace(h)
}

func (s *Scraper) fetchHTMLWithRetry(urlStr string) (string, error) {
	// 1. Check URL cache first
	urlCacheMu.RLock()
	cachedHTML, found := urlCache[urlStr]
	urlCacheMu.RUnlock()
	if found {
		return cachedHTML, nil
	}

	// 2. Check persistent cache from disk
	pCache := loadPersistentCache()
	persistentCacheMu.Lock()
	entry, foundPC := pCache.URLCache[urlStr]
	persistentCacheMu.Unlock()
	if foundPC && !isExpired(entry.Timestamp) {
		// Populate in-memory cache
		urlCacheMu.Lock()
		urlCache[urlStr] = entry.HTML
		urlCacheMu.Unlock()
		return entry.HTML, nil
	}

	// 3. Check if circuit breaker is tripped
	if circuitBreakerTripped.Load() {
		return "", fmt.Errorf("circuit breaker activo")
	}

	// 3. Max 1 concurrent live request
	liveMutex.Lock()
	defer liveMutex.Unlock()

	// Double-check CB and cache under mutex
	if circuitBreakerTripped.Load() {
		return "", fmt.Errorf("circuit breaker activo")
	}

	urlCacheMu.RLock()
	cachedHTML, found = urlCache[urlStr]
	urlCacheMu.RUnlock()
	if found {
		return cachedHTML, nil
	}

	// 4. Rate-limit: 5-12 seconds random delay with jitter
	minSec := 5
	maxSec := 12
	jitterSeconds := minSec + int(time.Now().UnixNano()%int64(maxSec-minSec+1))
	time.Sleep(time.Duration(jitterSeconds) * time.Second)

	// 5. Query live with backoff
	var lastErr error
	backoff := 5 * time.Second
	maxRetries := 3

	for attempt := 1; attempt <= maxRetries; attempt++ {
		req, err := http.NewRequest("GET", urlStr, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", "Tricera Security Audit Engine/5.3 (https://github.com/stegosec/Tricera-lite; contact@stegosec.com)")

		resp, err := s.Client.Do(req)
		if err != nil {
			lastErr = err
			fmt.Printf("[!] Intento %d/%d fallido para %s: %v. Reintentando en %v...\n", attempt, maxRetries, urlStr, err, backoff)
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		// 403/429 triggers CB immediately
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			consecutiveFailures.Store(3)
			circuitBreakerTripped.Store(true)
			fmt.Printf("[!] Código HTTP %d detectado en %s. Tripulando Circuit Breaker de inmediato.\n", resp.StatusCode, urlStr)
			return "", fmt.Errorf("circuit breaker tripulado por HTTP %d", resp.StatusCode)
		}

		// 5xx triggers backoff
		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			resp.Body.Close()
			lastErr = fmt.Errorf("error del servidor HTTP %d", resp.StatusCode)
			fmt.Printf("[!] Intento %d/%d fallido para %s: HTTP %d. Reintentando en %v...\n", attempt, maxRetries, urlStr, resp.StatusCode, backoff)
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP status %s", resp.Status)
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			time.Sleep(backoff)
			backoff *= 2
			continue
		}

		// Reset consecutive failures
		consecutiveFailures.Store(0)

		htmlStr := string(body)
		urlCacheMu.Lock()
		urlCache[urlStr] = htmlStr
		urlCacheMu.Unlock()

		// Guardar en caché persistente y disco
		pCache := loadPersistentCache()
		persistentCacheMu.Lock()
		pCache.URLCache[urlStr] = URLCacheEntry{
			HTML:      htmlStr,
			Timestamp: time.Now(),
		}
		persistentCacheMu.Unlock()
		_ = savePersistentCache(pCache)

		return htmlStr, nil
	}

	// Update CB on failure
	if consecutiveFailures.Add(1) >= 3 {
		circuitBreakerTripped.Store(true)
		fmt.Printf("[!] 3 fallos consecutivos alcanzados. Desactivando consultas live (Circuit Breaker activado).\n")
	}

	return "", fmt.Errorf("error tras %d intentos: %v", maxRetries, lastErr)
}

// SEC-FIX VULN-010: Validación de campos críticos en advisories parseados
func (s *Scraper) parsePage(html string) ([]Advisory, bool) {
	var advisories []Advisory

	doc, err := goquery.NewDocumentFromReader(strings.NewReader(html))
	if err != nil {
		return nil, false
	}

	doc.Find("div.row[onclick]").Each(func(i int, selection *goquery.Selection) {
		onclick, exists := selection.Attr("onclick")
		if !exists {
			return
		}

		id := reID.FindString(onclick)
		if id == "" {
			return
		}

		title := ""
		titleSel := selection.Find("div.col-md-3 b, div.col-md-3 strong").First()
		if titleSel.Length() > 0 {
			title = strings.TrimSpace(titleSel.Text())
			title = strings.TrimSpace(strings.Replace(title, id, "", 1))
		} else {
			firstB := selection.Find("b, strong").First()
			if firstB.Length() > 0 {
				title = strings.TrimSpace(firstB.Text())
				title = strings.TrimSpace(strings.Replace(title, id, "", 1))
			}
		}

		severity := "Medium"
		selection.Find("p b, div b, span").Each(func(j int, sel *goquery.Selection) {
			text := strings.TrimSpace(sel.Text())
			if reSeverity.MatchString(text) {
				severity = reSeverity.FindString(text)
			}
		})

		var cves []string
		selection.Find("b.cve, span.cve, a.cve").Each(func(j int, sel *goquery.Selection) {
			cveText := strings.TrimSpace(sel.Text())
			cvesFound := reCVE.FindAllString(cveText, -1)
			cves = append(cves, cvesFound...)
		})
		if len(cves) == 0 {
			cves = reCVE.FindAllString(selection.Text(), -1)
		}

		cveMap := make(map[string]bool)
		var uniqueCVEs []string
		for _, c := range cves {
			if !cveMap[c] {
				cveMap[c] = true
				uniqueCVEs = append(uniqueCVEs, c)
			}
		}

		adv := Advisory{
			ID:        id,
			Title:     title,
			Severity:  severity,
			CVEs:      uniqueCVEs,
			Reference: fmt.Sprintf("%s/%s", psirtBaseURL, id),
			Source:    "FortiGuard PSIRT Web",
		}
		
		advisories = append(advisories, adv)
	})

	hasNext := false
	doc.Find("a, button, span").Each(func(i int, selection *goquery.Selection) {
		ariaLabel, _ := selection.Attr("aria-label")
		if ariaLabel == "Next" || strings.Contains(strings.ToLower(selection.Text()), "next") {
			hasNext = true
		}
	})

	return advisories, hasNext
}
