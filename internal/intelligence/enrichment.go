package intelligence

import (
	"fmt"
	"strings"
	"time"
)

func EnrichAdvisory(adv Advisory, asset AssetFingerprint) ThreatEnrichment {
	enrich := ThreatEnrichment{
		PSIRTID:           adv.ID,
		Title:             adv.Title,
		VendorSeverity:    adv.Severity,
		CVSS:              adv.CVSS,
		VendorWorkaround:  BuildWorkaroundText(adv),
		VendorSolution:    "Actualizar FortiOS hacia una versión corregida indicada por Fortinet en el advisory oficial.",
		EvidenceSummary:   adv.EvidenceSummary,
		Sources: []ThreatSource{
			{Name: "FortiGuard PSIRT", URL: adv.Reference, RetrievedAt: time.Now().Format(time.RFC3339), Confidence: "Alta"},
		},
		IntelSource:       adv.Source,
	}

	if len(adv.CVEs) > 0 {
		enrich.CVE = adv.CVEs[0]
		// 1. CISA KEV
		if kev, ok := FetchCisaKevByCVE(enrich.CVE); ok {
			enrich.IsCisaKEV = true
			enrich.KnownExploited = true
			enrich.ExploitStatus = "Explotación conocida documentada por CISA"
			enrich.CisaKevDueDate = kev.DueDate
			enrich.Sources = append(enrich.Sources, ThreatSource{
				Name: "CISA KEV", URL: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", RetrievedAt: time.Now().Format(time.RFC3339), Confidence: "Crítica",
			})
		} else {
			enrich.ExploitStatus = "No observado en CISA KEV al momento del análisis"
		}

		// 2. EPSS Integration
		if epss, err := FetchEPSS(enrich.CVE); err == nil {
			enrich.EPSSScore = epss.Score
			enrich.EPSSPercentile = epss.Percentile
			enrich.Sources = append(enrich.Sources, ThreatSource{
				Name: "FIRST EPSS", URL: "https://www.first.org/epss", RetrievedAt: time.Now().Format(time.RFC3339), Confidence: "Estadística",
			})
		}
	}

	state := ApplicableByVersion
	if strings.Contains(adv.EvidenceSummary, "confirmada") || strings.Contains(adv.EvidenceSummary, "línea") {
		state = ExposureConfirmed
	}

	// 3. Tricera Threat Priority (TTP) calculation
	priority, ttpScore := CalculateTriceraPriority(adv, enrich, state)
	enrich.TriceraPriority = priority
	enrich.TTPScore = ttpScore

	enrich.RecommendedAction = BuildRecommendedAction(adv, enrich, state)
	enrich.ImmediateAction = buildImmediateAction(adv, enrich, state)
	enrich.ValidationAction = buildValidationAction(adv, enrich, state)
	enrich.LongTermAction = buildLongTermAction(adv, enrich, state)
	enrich.BusinessImpact = buildBusinessImpact(adv, enrich, state)

	return enrich
}

func CalculateTriceraPriority(adv Advisory, enrich ThreatEnrichment, state FindingState) (string, int) {
	score := 0
	
	// Base CVSS or Severity
	if strings.Contains(adv.Severity, "Critical") || strings.Contains(adv.Severity, "Crítico") { score += 40 }
	if strings.Contains(adv.Severity, "High") || strings.Contains(adv.Severity, "Alto") { score += 30 }

	// CISA KEV (Massive boost)
	if enrich.IsCisaKEV { score += 50 }

	// EPSS (Probabilistic boost)
	if enrich.EPSSScore > 0.1 { score += 20 }
	if enrich.EPSSScore > 0.5 { score += 20 }

	// Contextual Boost
	if state == ExposureConfirmed { score += 30 }

	comp := strings.ToUpper(adv.Component)
	if strings.Contains(comp, "SSL-VPN") || strings.Contains(comp, "GUI") || strings.Contains(comp, "SSO") {
		score += 20 // Componente crítico expuesto
	}

	if score > 100 { score = 100 }

	// Clasificación Final
	switch {
	case score >= 90:  return "P1 CRÍTICO", score
	case score >= 70:  return "P2 ALTO", score
	case score >= 40:  return "P3 MEDIO", score
	default:           return "P4 BAJO", score
	}
}

func BuildRecommendedAction(adv Advisory, enrich ThreatEnrichment, state FindingState) string {
	if state == ExposureConfirmed {
		return "Atención inmediata. Restringir temporalmente el acceso al componente, aplicar mitigación táctica, validar indicadores de compromiso y actualizar a versión corregida."
	}
	return "Priorizar validación y actualización. Aunque Tricera no confirmó exposición desde el backup, el firmware auditado aparece dentro de las versiones afectadas."
}

func buildImmediateAction(adv Advisory, enrich ThreatEnrichment, state FindingState) string {
	comp := strings.ToUpper(adv.Component)
	title := strings.ToUpper(adv.Title)
	
	switch {
	case strings.Contains(comp, "SSO") || strings.Contains(comp, "GUI") || strings.Contains(title, "SSO") || strings.Contains(title, "GUI"):
		return "Restringir acceso GUI/HTTPS a redes de administración confiables, revisar trusted hosts, implementar Local-In Policies, validar MFA para cuentas administrativas y revisar logs de autenticación."
	case strings.Contains(comp, "CAPWAP") || strings.Contains(comp, "WIRELESS") || strings.Contains(title, "CAPWAP") || strings.Contains(title, "WIRELESS"):
		return "Validar si wireless-controller o FortiAP están en uso, restringir administración CAPWAP a segmentos internos, segmentar tráfico de APs y revisar exposición de puertos CAPWAP."
	case strings.Contains(comp, "SSH") || strings.Contains(comp, "CLI") || strings.Contains(title, "SSH") || strings.Contains(title, "CLI"):
		return "Restringir SSH/CLI a redes administrativas, validar trusted hosts, revisar cuentas super_admin y revisar logs de administración."
	case strings.Contains(comp, "SSL-VPN") || strings.Contains(comp, "SSLVPN") || strings.Contains(title, "SSL-VPN") || strings.Contains(title, "SSLVPN"):
		return "Validar si SSL-VPN está habilitado, restringir source-address, exigir MFA, deshabilitar web mode si no se usa y revisar logs VPN."
	case strings.Contains(comp, "LDAP") || strings.Contains(comp, "FSSO") || strings.Contains(title, "LDAP") || strings.Contains(title, "FSSO"):
		return "Revisar servidores LDAP/FSSO configurados, validar wildcard admins, limitar grupos remotos y revisar perfiles administrativos."
	case strings.Contains(comp, "ZTNA") || strings.Contains(comp, "PROXY") || strings.Contains(title, "ZTNA") || strings.Contains(title, "PROXY"):
		return "Revisar access-proxy, validar certificados de cliente, revisar políticas ZTNA y restringir exposición externa."
	case strings.Contains(comp, "WEB FILTER") || strings.Contains(title, "WEB FILTER") || strings.Contains(title, "WEB-FILTER"):
		return "Revisar perfiles Web Filter, validar warning pages y revisar exposición del portal."
	case strings.Contains(comp, "KERNEL") || strings.Contains(comp, "DAEMON") || strings.Contains(comp, "MEMORIA") || strings.Contains(title, "KERNEL") || strings.Contains(title, "OVERFLOW"):
		return "Priorizar actualización, monitorear estabilidad, revisar logs de sistema y validar si el servicio asociado está activo."
	default:
		return "Actualizar a versión corregida y validar advisory oficial. Debido a que el componente no fue identificado automáticamente, requiere revisión manual de alcance."
	}
}

func buildValidationAction(adv Advisory, enrich ThreatEnrichment, state FindingState) string {
	if enrich.IsCisaKEV {
		return "Buscar indicadores de compromiso (IoCs) en logs de sistema y tráfico. Auditar sesiones administrativas recientes."
	}
	return "Verificar logs de eventos del sistema y validar si el servicio asociado está en uso activo."
}

func buildLongTermAction(adv Advisory, enrich ThreatEnrichment, state FindingState) string {
	return fmt.Sprintf("Actualizar FortiOS desde la versión actual hacia una versión corregida indicada por Fortinet para el advisory %s. Validar compatibilidad y programar ventana de mantenimiento.", adv.ID)
}

func buildBusinessImpact(adv Advisory, enrich ThreatEnrichment, state FindingState) string {
	if enrich.IsCisaKEV {
		return "Riesgo crítico de compromiso total del dispositivo. La explotación activa documentada aumenta drásticamente la probabilidad de un ataque."
	}
	return "Riesgo de seguridad en el componente. Un atacante podría aprovechar esta debilidad para comprometer la disponibilidad o integridad del servicio."
}

func BuildWorkaroundText(adv Advisory) string {
	if adv.Workaround != "" && !strings.Contains(strings.ToLower(adv.Workaround), "no publicado") && !strings.Contains(strings.ToLower(adv.Workaround), "no identificado") {
		return adv.Workaround
	}
	
	comp := strings.ToUpper(adv.Component)
	title := strings.ToUpper(adv.Title)
	
	switch {
	case strings.Contains(comp, "SSO") || strings.Contains(comp, "GUI") || strings.Contains(title, "SSO") || strings.Contains(title, "GUI"):
		return "No se identificó workaround oficial. Mitigación temporal: restringir exposición administrativa y limitar acceso GUI/HTTPS a redes confiables hasta aplicar actualización."
	case strings.Contains(comp, "CAPWAP") || strings.Contains(comp, "WIRELESS") || strings.Contains(title, "CAPWAP") || strings.Contains(title, "WIRELESS"):
		return "No se identificó workaround oficial. Mitigación temporal: limitar comunicación CAPWAP a redes confiables y deshabilitar funciones wireless no utilizadas."
	case strings.Contains(comp, "SSH") || strings.Contains(comp, "CLI") || strings.Contains(title, "SSH") || strings.Contains(title, "CLI"):
		return "Restringir acceso administrativo y aplicar controles de mínimo privilegio hasta actualizar."
	default:
		return "No se identificó workaround específico en la fuente consultada. La acción recomendada es aplicar la versión corregida indicada por Fortinet."
	}
}
