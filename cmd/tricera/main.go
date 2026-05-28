package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"tricera/internal/engine"
	"tricera/internal/intelligence"
	"tricera/internal/matcher"
	"tricera/internal/parser"
	"tricera/internal/report"
	"tricera/internal/system"
	"tricera/internal/ui"
)

func main() {
	// Limpieza silenciosa: eliminar backup .old de actualizaciones previas
	system.CleanupPreviousUpdate()

	// Propagar la versión inyectada por ldflags al banner de la UI
	ui.BannerVersion = system.Version

	filePath := flag.String("file", "", "Archivo .conf")
	rulesPath := flag.String("rules", "", "Reglas JSON adicionales")
	format := flag.String("format", "text", "Formato: text, json, html")
	debug := flag.Bool("debug", false, "Modo Debug")
	update := flag.Bool("update", false, "Instrucciones de actualización")
	autoUpdate := flag.Bool("auto-update", false, "Descarga y actualiza el binario de forma segura (HTTPS + minisign)")
	showVersion := flag.Bool("version", false, "Muestra la versión actual del binario")
	outPath := flag.String("out", "", "Archivo de salida")
	comparePath := flag.String("compare", "", "Archivo .conf anterior para análisis diferencial")
	intelSource := flag.String("intel-source", "offline", "Fuente de inteligencia PSIRT: live, offline")
	hardeningGuide := flag.Bool("hardening-guide", false, "Muestra la guía rápida interactiva de hardening para la comunidad")

	flag.Usage = func() {
		ui.PrintBanner()
		fmt.Printf("%sMenú de Uso de Tricera:%s\n", ui.Bold+ui.Cyan, ui.Reset)
		fmt.Printf("  tricera.exe -file <archivo.conf> [opciones]\n\n")
		fmt.Printf("%s[ Parámetros de Auditoría ]%s\n", ui.Bold, ui.Reset)
		fmt.Printf("  -file <ruta>          Archivo .conf del FortiGate a auditar (Requerido)\n")
		fmt.Printf("  -format <formato>     Formato del reporte: text, json, html (por defecto: text)\n")
		fmt.Printf("  -out <ruta>           Archivo de salida para el reporte guardado (ej: reporte.html)\n")
		fmt.Printf("  -compare <ruta>       Archivo .conf anterior para análisis diferencial de cambios\n")
		fmt.Printf("  -rules <ruta>         Archivo JSON con reglas de hardening adicionales personalizadas\n")
		fmt.Printf("  -update               Muestra las instrucciones manuales de actualización del motor Tricera\n")
		fmt.Printf("  -auto-update          Descarga y actualiza el binario automáticamente (HTTPS + firma minisign)\n")
		fmt.Printf("  -version              Muestra la versión actual del binario\n")
		fmt.Printf("  -debug                Activa el modo de depuración detallada en consola\n\n")
		fmt.Printf("%s[ Modos de Inteligencia (PSIRT) ]%s\n", ui.Bold, ui.Reset)
		fmt.Printf("  -intel-source <modo>  Define el canal de consulta de amenazas:\n")
		fmt.Printf("      > %soffline%s  (Rápido - 10 a 60 segundos) %s[RECOMENDADO]%s\n", ui.Bold+ui.Green, ui.Reset, ui.Bold+ui.Yellow, ui.Reset)
		fmt.Printf("                  Usa el catálogo local offline embebido en el binario.\n")
		fmt.Printf("                  Ideal para auditorías diarias rápidas sin acceso a internet.\n")
		fmt.Printf("      > %slive%s     (Detallado - Varios minutos)\n", ui.Bold+ui.Cyan, ui.Reset)
		fmt.Printf("                  Consulta FortiGuard Live en vivo con tasa responsable (rate-limit).\n")
		fmt.Printf("                  Uso para auditorías de cumplimiento periódicas o profundas.\n\n")
		fmt.Printf("%s[ Opciones de la Comunidad ]%s\n", ui.Bold, ui.Reset)
		fmt.Printf("  -hardening-guide      Imprime una guía rápida interactiva sobre cómo asegurar FortiOS\n\n")
	}

	flag.Parse()

	if *outPath != "" && *format == "text" {
		lowerOut := strings.ToLower(*outPath)
		if strings.HasSuffix(lowerOut, ".html") || strings.HasSuffix(lowerOut, ".htm") {
			*format = "html"
		} else if strings.HasSuffix(lowerOut, ".json") {
			*format = "json"
		}
	}

	if *showVersion {
		fmt.Printf("Tricera v%s (%s/%s)\n", system.Version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if *hardeningGuide {
		ui.PrintHardeningGuide()
		os.Exit(0)
	}

	if *filePath == "" && !*update && !*autoUpdate && *comparePath == "" {
		flag.Usage()
		os.Exit(0)
	}

	ui.PrintBanner()

	if strings.ToLower(*intelSource) == "live" {
		intelligence.LiveEnabled = true
	} else {
		intelligence.LiveEnabled = false
	}

	if *update {
		system.PrintUpdateInstructions()
		os.Exit(0)
	}

	if *autoUpdate {
		ui.PrintBanner()
		if err := system.RunSecureUpdate(system.DefaultUpdateURL); err != nil {
			ui.FatalError("Auto-actualización segura fallida", err.Error())
		}
		os.Exit(0)
	}

	rules := engine.GetHardeningRules()
	if *rulesPath != "" {
		local, err := engine.LoadRules(*rulesPath)
		if err != nil {
			ui.PrintWarning(fmt.Sprintf("No se pudieron cargar las reglas adicionales desde %s: %v. Se continuará con las reglas base.", *rulesPath, err))
		} else {
			rules = append(rules, local...)
		}
	}

	if *comparePath != "" && *filePath != "" {
		performDiffAudit(*comparePath, *filePath, rules, *debug)
		os.Exit(0)
	}

	if *filePath != "" {
		runSingleAudit(*filePath, rules, *format, *outPath, *debug, *format != "json")
	} else {
		ui.FatalError("Sin objetivo", "Usa -file para indicar qué archivo .conf auditar.")
	}
}

// SEC-FIX VULN-003: Validar extensión del archivo para prevenir lectura de archivos arbitrarios
// SEC-FIX A-02: Validar tamaño del archivo para prevenir agotamiento de memoria
const maxConfFileSize = 100 * 1024 * 1024 // 100MB

func validateConfPath(path string) string {
	if !strings.HasSuffix(strings.ToLower(path), ".conf") {
		ui.FatalError("Archivo inválido", "Solo se permiten archivos con extensión .conf")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		ui.FatalError("Ruta inválida", err.Error())
	}
	info, err := os.Stat(absPath)
	if err != nil {
		ui.FatalError("No se puede acceder al archivo", err.Error())
	}
	if info.Size() > maxConfFileSize {
		ui.FatalError("Archivo demasiado grande",
			fmt.Sprintf("El archivo .conf excede el límite de %dMB. Tamaño: %dMB.",
				maxConfFileSize/(1024*1024), info.Size()/(1024*1024)))
	}
	return absPath
}

func runSingleAudit(path string, rules []engine.Rule, format, out string, debug bool, dino bool) {
	startTime := time.Now()
	
	if dino {
		ui.PlayAuditProgressBarDino(5, "Validando rutas y abriendo archivo .conf...")
	}

	path = validateConfPath(path)
	f, err := os.Open(path)
	if err != nil {
		ui.FatalError("Error al abrir archivo de configuración", err.Error())
	}
	defer f.Close()

	if dino {
		ui.PlayAuditProgressBarDino(20, "Parseando archivo .conf del FortiGate...")
	}

	cfg, err := parser.ParseConfigFile(f, debug)
	if err != nil {
		ui.FatalError("Error al analizar archivo de configuración", err.Error())
	}
	if !dino {
		ui.PrintSuccess(fmt.Sprintf("Auditoría iniciada: %s (v%s)", cfg.Hostname, cfg.Version))
	}

	if dino {
		ui.PlayAuditProgressBarDino(40, "Cargando catálogos CISA KEV y base PSIRT...")
	}

	// Inteligencia PSIRT + KEV + EPSS
	kevMap, errK := intelligence.FetchCisaKev()
	if errK != nil && !dino {
		ui.PrintWarning(fmt.Sprintf("No se pudo obtener el catálogo CISA KEV (offline/error): %v. Se continuará sin enriquecimiento KEV.", errK))
	}
	scraper := intelligence.NewScraper()
	advisories, errA := scraper.FetchAdvisories("FortiOS-6K7K,FortiOS", cfg.Version)
	var psirtFindings []matcher.PSIRTFinding
	if errA != nil {
		if !dino {
			ui.PrintWarning(fmt.Sprintf("No se pudieron consultar los advisories de FortiGuard (offline/error): %v. Se omitirá el análisis PSIRT.", errA))
		}
		psirtFindings = []matcher.PSIRTFinding{
			{
				Advisory: intelligence.Advisory{
					ID:          "ERROR_FETCH",
					Description: errA.Error(),
				},
			},
		}
	} else {
		for i := range advisories {
			intelligence.NormalizeAdvisory(&advisories[i])
			if errK == nil && len(advisories[i].CVEs) > 0 && kevMap[advisories[i].CVEs[0]] {
				advisories[i].IsExploited = true
			}
		}
		psirtFindings = matcher.MatchAdvisories(cfg.Version, advisories, cfg)
	}

	if dino {
		ui.PlayAuditProgressBarDino(65, "Cruzando y filtrando vulnerabilidades de firmware...")
	}

	if dino {
		ui.PlayAuditProgressBarDino(80, "Evaluando políticas de hardening y robustez de hashes...")
	}

	var results []engine.CheckResult
	for _, r := range rules {
		results = append(results, engine.Evaluate(cfg.Hostname, cfg.Version, cfg, r, debug)...)
	}
	results = append(results, engine.DiscoverTopology(cfg.Hostname, cfg)...)
	results = append(results, engine.AnalyzeFirewallIntelligence(cfg.Hostname, cfg)...)
	results = append(results, engine.AnalyzeObjectIntelligence(cfg.Hostname, cfg)...)

	if dino {
		ui.PlayAuditProgressBarDino(95, "Compilando reporte técnico y métricas de compliance...")
	}

	if dino {
		ui.PlayAuditProgressBarDino(100, "¡Auditoría de Fortinet completada con éxito!")
	}

	duration := time.Since(startTime)
	printEvidenceReport(results, psirtFindings, cfg.Hostname, cfg.Version, duration)
	if out != "" && format == "html" {
		err := report.ExportHTML(results, psirtFindings, cfg.Version, cfg, out, nil, duration)
		if err != nil {
			ui.FatalError("Error al generar reporte HTML", err.Error())
		}
		ui.PrintSuccess(fmt.Sprintf("Reporte generado con éxito: %s", out))
	}
	ui.PrintSuccess(fmt.Sprintf("Auditoría completada con éxito en %.2fs!", duration.Seconds()))
}

func performDiffAudit(oldPath, newPath string, rules []engine.Rule, debug bool) {
	oldPath = validateConfPath(oldPath)
	newPath = validateConfPath(newPath)
	ui.PrintInfo("Iniciando Análisis Diferencial (Fase 4)...")
	
	// Analizar A
	fOld, err := os.Open(oldPath)
	if err != nil {
		ui.FatalError("Error al abrir archivo de configuración antiguo", err.Error())
	}
	cfgOld, err := parser.ParseConfigFile(fOld, debug)
	fOld.Close()
	if err != nil {
		ui.FatalError("Error al analizar archivo de configuración antiguo", err.Error())
	}
	var resOld []engine.CheckResult
	for _, r := range rules {
		resOld = append(resOld, engine.Evaluate("OLD", cfgOld.Version, cfgOld, r, debug)...)
	}

	// Analizar B
	fNew, err := os.Open(newPath)
	if err != nil {
		ui.FatalError("Error al abrir archivo de configuración nuevo", err.Error())
	}
	cfgNew, err := parser.ParseConfigFile(fNew, debug)
	fNew.Close()
	if err != nil {
		ui.FatalError("Error al analizar archivo de configuración nuevo", err.Error())
	}
	var resNew []engine.CheckResult
	for _, r := range rules {
		resNew = append(resNew, engine.Evaluate("NEW", cfgNew.Version, cfgNew, r, debug)...)
	}

	diff := engine.CompareAudits(resOld, resNew)

	fmt.Printf("\n%s═══ DELTA DE SEGURIDAD ═══%s\n", ui.Bold, ui.Reset)
	
	if len(diff.Removed) > 0 {
		fmt.Printf("\n%s[✓] RIESGOS RESUELTOS (%d):%s\n", ui.Green, len(diff.Removed), ui.Reset)
		for _, r := range diff.Removed {
			fmt.Printf("    - %s\n", r.Title)
		}
	}

	if len(diff.Added) > 0 {
		fmt.Printf("\n%s[!] NUEVOS RIESGOS INTRODUCIDOS (%d):%s\n", ui.Red, len(diff.Added), ui.Reset)
		for _, r := range diff.Added {
			fmt.Printf("    - %s (Línea %d)\n", r.Title, r.Line)
		}
	}

	if len(diff.Modified) > 0 {
		fmt.Printf("\n%s[*] RIESGOS MODIFICADOS (%d):%s\n", ui.Yellow, len(diff.Modified), ui.Reset)
		for _, r := range diff.Modified {
			fmt.Printf("    - %s (Cambio de valor detectado)\n", r.Title)
		}
	}

	if len(diff.Added) == 0 && len(diff.Removed) == 0 && len(diff.Modified) == 0 {
		ui.PrintSuccess("No se detectaron cambios en la postura de seguridad.")
	}
}

func printEvidenceReport(results []engine.CheckResult, psirt []matcher.PSIRTFinding, deviceName, version string, duration time.Duration) {
	var fails, passes, mitigated, unverified int
	for _, r := range results {
		switch {
		case !r.Passed && r.Status != "MITIGADO" && r.Status != "NO VERIFICADO": fails++
		case r.Status == "MITIGADO": mitigated++
		case r.Status == "NO VERIFICADO": unverified++
		case r.Passed: passes++
		}
	}

	// 1. Mostrar riesgos de hardening
	if fails > 0 {
		fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", ui.Bold, ui.Red, ui.Reset)
		fmt.Printf("%s%s║                         RIESGOS DE SEGURIDAD IDENTIFICADOS                   ║%s\n", ui.Bold, ui.Red, ui.Reset)
		fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n", ui.Bold, ui.Red, ui.Reset)
		for _, r := range results {
			if !r.Passed && r.Status != "MITIGADO" && r.Status != "NO VERIFICADO" {
				severityColor := ui.Red
				if r.Status == "MEDIO" {
					severityColor = ui.Yellow
				} else if r.Status == "BAJO" {
					severityColor = ui.Cyan
				}
				fmt.Printf("\n%s[%s]%s %s%s%s\n", severityColor, r.Status, ui.Reset, ui.Bold, r.Title, ui.Reset)
				fmt.Printf("  ├── %sEvidencia:%s  %s\n", ui.Cyan, ui.Reset, r.Evidence)
				if r.CLIScript != "" {
					indentedCLI := strings.ReplaceAll(r.CLIScript, "\n", "\n      ")
					fmt.Printf("  └── %sRemediación CLI (Dinámica):%s\n      %s\n", ui.Green, ui.Reset, indentedCLI)
				} else if r.QuickFix != "" {
					fmt.Printf("  └── %sRemediación (Genérica):%s %s\n", ui.Green, ui.Reset, r.QuickFix)
				}
			}
		}
	}

	// 2. Mostrar vulnerabilidades PSIRT
	var activeVulns int
	for _, p := range psirt {
		if p.Advisory.ID != "" && p.Advisory.ID != "ERROR_FETCH" {
			activeVulns++
		}
	}

	if activeVulns > 0 {
		fmt.Printf("\n%s%s╔══════════════════════════════════════════════════════════════════════════════╗%s\n", ui.Bold, ui.Yellow, ui.Reset)
		fmt.Printf("%s%s║                         VULNERABILIDADES PSIRT DETECTADAS                    ║%s\n", ui.Bold, ui.Yellow, ui.Reset)
		fmt.Printf("%s%s╚══════════════════════════════════════════════════════════════════════════════╝%s\n", ui.Bold, ui.Yellow, ui.Reset)
		for _, p := range psirt {
			if p.Advisory.ID == "" || p.Advisory.ID == "ERROR_FETCH" {
				continue
			}
			
			severityColor := ui.Red
			if p.Advisory.Severity == "Medium" {
				severityColor = ui.Yellow
			} else if p.Advisory.Severity == "Low" {
				severityColor = ui.Cyan
			}

			cveStr := "CVE-N/A"
			if len(p.Advisory.CVEs) > 0 {
				cveStr = p.Advisory.CVEs[0]
			}

			kevTag := ""
			if p.Advisory.IsExploited {
				kevTag = " [CISA KEV]"
			}

			// Determinar estado de exposición
			stateStr := "Potencial por Versión"
			stateColor := ui.Cyan
			if p.State == intelligence.ExposureConfirmed {
				stateStr = "CONFIRMADA (ACTIVA EN CONFIGURACIÓN)"
				stateColor = ui.Red
			} else if p.State == intelligence.ManualReviewRequired {
				stateStr = "Revisión Manual Requerida"
				stateColor = ui.Yellow
			} else if p.State == intelligence.NotApplicableByConfig {
				stateStr = "Mitigado por Configuración (Inactivo)"
				stateColor = ui.Green
			}

			sourceTag := "Offline"
			if p.Advisory.Enrichment.IntelSource == "live" {
				sourceTag = "Live"
			} else if p.Advisory.Enrichment.IntelSource == "fallback" {
				sourceTag = "Resguardo"
			}

			remediation := p.Advisory.RecommendedAction
			if remediation == "" {
				remediation = p.Advisory.Enrichment.RecommendedAction
			}
			if remediation == "" {
				remediation = p.Advisory.VendorSolution
			}

			fmt.Printf("\n%s[%s]%s %s%s (%s)%s%s\n", severityColor, strings.ToUpper(p.Advisory.Severity), ui.Reset, ui.Bold, p.Advisory.ID, cveStr, kevTag, ui.Reset)
			fmt.Printf("  ├── %sExposición:%s  %s%s%s (Procedencia: %s)\n", ui.Cyan, ui.Reset, stateColor, stateStr, ui.Reset, sourceTag)
			fmt.Printf("  ├── %sDescripción:%s %s\n", ui.Cyan, ui.Reset, p.Advisory.Description)
			if remediation != "" {
				fmt.Printf("  └── %sRemediación:%s %s\n", ui.Green, ui.Reset, remediation)
			}
		}
	}

	// Dashboard Ejecutivo de StegoSec Tricera
	fmt.Printf("\n%s", ui.Cyan)
	fmt.Println("┌────────────────────────────────────────────────────────┐")
	fmt.Printf("│  %s%-52s%s  │\n", ui.Bold+ui.Green, "STEGOSEC TRICERA AUDIT COMPLETED", ui.Reset+ui.Cyan)
	fmt.Println("├────────────────────────────────────────────────────────┤")
	fmt.Printf("│  Device Name:   %-38s │\n", deviceName)
	fmt.Printf("│  Version:       %-38s │\n", "v"+version)
	fmt.Printf("│  Duration:      %-38s │\n", fmt.Sprintf("%.2fs", duration.Seconds()))
	fmt.Println("├────────────────────────────────────────────────────────┤")
	fmt.Printf("│  %s[✗] Risks Identified:   %-28d%s │\n", ui.Red, fails, ui.Cyan)
	fmt.Printf("│  %s[✓] Passed Controls:    %-28d%s │\n", ui.Green, passes, ui.Cyan)
	fmt.Printf("│  %s[!] Mitigated Risks:    %-28d%s │\n", ui.Yellow, mitigated, ui.Cyan)
	fmt.Printf("│  %s[?] Unverified:         %-28d%s │\n", ui.Cyan, unverified, ui.Cyan)
	fmt.Println("└────────────────────────────────────────────────────────┘")
	fmt.Printf("%s\n", ui.Reset)
}
