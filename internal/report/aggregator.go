package report

import (
	"fmt"
	"strings"
	"time"
	"tricera/internal/engine"
	"tricera/internal/intelligence"
	"tricera/internal/parser"
)

type FindingGroup struct {
	GroupID         string
	Title           string
	Category        string
	Severity        string
	Priority        string
	Summary         string
	BusinessImpact  string
	TechnicalImpact string
	Recommendation  string
	ValidationStep  string
	AffectedCount   int
	AffectedItems   []AffectedItem
	RemediationCLI  []string
}

type AffectedItem struct {
	Name           string
	VDOM           string
	PolicyID       string
	Interface      string
	User           string
	Line           int
	Value          string
	Recommended    string
	Evidence       string
	RemediationCLI string
	Impact         string
	Status         string
}

type AuditCoverageSummary struct {
	Hostname              string
	Model                 string
	Serial                string
	FirmwareVersion       string
	Build                 int
	AnalysisDate          string
	SourceFile            string

	LinesProcessed        int
	SectionsParsed        int
	ParserErrors          int
	ParserWarnings        int

	VDOMCount             int
	VDOMs                 []string
	InterfaceCount        int
	FirewallPolicyCount   int
	AddressObjectCount    int
	AddressGroupCount     int
	ServiceObjectCount    int
	ServiceGroupCount     int
	AdminUserCount        int
	LocalInPolicyCount    int
	VIPCount              int
	IPPoolCount           int
	SSLVPNPortalCount     int
	IPsecPhase1Count      int
	IPsecPhase2Count      int
	SecurityProfileCount  int
	SecurityProfilesList  []string
	VLANsList             []string

	HADetected            bool
	SDWANDetected         bool
	FortiManagerDetected  bool
	SSLVPNDetected        bool
	IPsecDetected         bool

	CISTotalControls      int
	CISEvaluated          int
	CISPass               int
	CISFail               int
	CISWarning            int
	CISNotApplicable      int
	CISError              int
	CISScore              float64
	TechnicalFindings     int
	GroupedFindings       int

	PSIRTConsulted        int
	PSIRTApplicable       int
	UniqueCVEs            int
	PSIRTExposureConfirmed int
	PSIRTVersionOnly      int
	PSIRTCisaKEV          int
	PSIRTEPSSQueried      int
	PSIRTEPSSHigh         int
	PSIRTManualReview     int
	PSIRTNoEvidence       int
	PSIRTNotApplicable    int

	PolicyEnabled         int
	PolicyDisabled        int
	PolicyAnyAnyCritical  int
	PolicySrcAny          int
	PolicyDstAny          int
	PolicyServiceAll      int
	PolicyNoLogging       int
	PolicyNoUTM           int
	PolicyShadowed        int
	PolicyRedundant       int
	PolicyWithNAT         int
	PolicyToWAN           int

	HygieneScore          int
	HygieneLevel          string

	ObjectDuplicates      int
	ObjectOverlaps        int
	ObjectOrphans         int
	ServiceDuplicates     int
	ServiceOverlaps       int

	ISOControlsMapped     int
	ISOPass               int
	ISOFail               int
	ISONotEvaluable       int

	NISTControlsMapped    int
	NISTPass              int
	NISTFail              int
	NISTNotEvaluable      int

	PCIControlsMapped     int
	PCIPass               int
	PCIFail               int
	PCINotEvaluable       int

	ResilienceScore       int
	TopologyMermaid       string
}

type PolicyRiskProfile struct {
	PolicyID  string
	VDOM      string
	RiskClass string
	RiskScore int
}

var executiveNarratives = map[string]struct {
	Impact         string
	Recommendation string
}{
	"CIS-FGT-17": {
		Impact:         "Las cuentas con privilegios totales aumentan drásticamente el impacto ante el robo de credenciales, abuso interno o sesiones comprometidas.",
		Recommendation: "Reducir privilegios usando perfiles administrativos por rol. Mantener super_admin solo para cuentas break-glass protegidas con MFA.",
	},
	"CIS-FGT-12": {
		Impact:         "El uso de HTTP permite la interceptación de credenciales administrativas en texto claro dentro de la red corporativa.",
		Recommendation: "Deshabilitar HTTP en todas las interfaces. Usar exclusivamente HTTPS para la gestión del firewall.",
	},
	"CIS-FGT-11": {
		Impact:         "Telnet es un protocolo heredado e inseguro que transmite toda la comunicación, incluyendo contraseñas, en texto claro.",
		Recommendation: "Inhabilitar Telnet inmediatamente y migrar a SSH para administración por consola remota.",
	},
	"HYG-OBJ-01": {
		Impact:         "Los objetos no utilizados aumentan la complejidad de la configuración y pueden ocultar errores de seguridad o brechas de higiene.",
		Recommendation: "Eliminar los objetos huérfanos para simplificar la auditoría y mejorar el rendimiento de la gestión.",
	},
	"SEC-ADV-01": {
		Impact:         "La falta de MFA en cuentas administrativas facilita el acceso no autorizado mediante ataques de phishing o fuerza bruta.",
		Recommendation: "Implementar FortiToken o integración con SAML/MFA externo para todos los administradores.",
	},
}

func AggregateFindings(results []engine.CheckResult, cfg *parser.FGTConfig) []FindingGroup {
	groups := make(map[string]*FindingGroup)

	// 1. Agrupar hallazgos por ID de control para evitar repeticiones
	for _, res := range results {
		if res.Passed || res.Category == "TOPOLOGY" || res.Category == "INFO" {
			continue
		}

		group, ok := groups[res.ID]
		if !ok {
			cat := res.Section
			if res.ID == "INT-LOCALIN-01" { cat = "LOCAL-IN" }
			if res.ID == "INT-SHADOW-01" { cat = "SHADOW-RULES" }
			if res.ID == "INT-OBJ-DUP-01" || res.ID == "INT-SVC-DUP-01" { cat = "OBJ-HYGIENE" }

			group = &FindingGroup{
				GroupID:         res.ID,
				Title:           res.Title,
				Category:        cat,
				Severity:        mapSeverity(res.Status),
				Summary:         res.Title,
				BusinessImpact:  res.BusinessImpact,
				TechnicalImpact: res.TechnicalImpact,
				Recommendation:  res.Remediation,
				ValidationStep:  res.ValidationStep,
			}
			groups[res.ID] = group
		}

		group.AffectedCount++
		
		item := AffectedItem{
			Name:           res.DeviceName,
			Line:           res.Line,
			Value:          res.Value,
			Evidence:       res.Evidence,
			VDOM:           res.VDOM,
			RemediationCLI: res.QuickFix,
			Status:         res.Status,
		}
		if res.ID == "INT-LOCALIN-01" && res.FailedPath != "" {
			item.Name = res.FailedPath
		}
		if res.ID == "INT-SHADOW-01" || res.ID == "INT-BYPASS-01" || res.ID == "INT-SVC-INSECURE" || res.ID == "INT-DMZ-EXPOSED" {
			item.PolicyID = res.FailedPath
		}
		
		if group.Category == "IAM" {
			item.User = extractUser(res.Evidence)
		}

		group.AffectedItems = append(group.AffectedItems, item)
	}

	// 2. Análisis profundo de políticas (No duplicar con hallazgos base)
	var policyGroups []FindingGroup
	var hygieneGroups []FindingGroup
	if cfg != nil {
		policyGroups = analyzePolicyRisks(cfg)
		hygieneGroups = analyzeHygiene(cfg)
	}
	
	var finalGroups []FindingGroup
	for _, g := range groups {
		enrichNarrative(g)
		finalGroups = append(finalGroups, *g)
	}

	for _, g := range policyGroups {
		finalGroups = append(finalGroups, g)
	}
	
	finalGroups = append(finalGroups, hygieneGroups...)

	return finalGroups
}

func BuildAuditCoverageSummary(cfg *parser.FGTConfig, results []engine.CheckResult, enriched []intelligence.ThreatEnrichment) AuditCoverageSummary {
	if cfg == nil {
		s := AuditCoverageSummary{
			Hostname:        "Auditoría Consolidada Masiva",
			Model:           "Múltiples Modelos",
			Serial:          "Múltiples Números de Serie",
			FirmwareVersion: "Múltiples Versiones",
			Build:           0,
			AnalysisDate:    time.Now().Format("02 Jan 2006"),
			LinesProcessed:  0,
			VDOMs:           []string{"root"},
			VDOMCount:       1,
			HADetected:      false,
			SDWANDetected:   false,
		}
		// Count controls evaluated
		for _, r := range results {
			if r.Category == "HARDENING" {
				s.CISEvaluated++
				if r.Passed { s.CISPass++ } else { s.CISFail++ }
				if r.ISO27001 != "" { s.ISOControlsMapped++; if r.Passed { s.ISOPass++ } else { s.ISOFail++ } }
				if r.NIST != "" { s.NISTControlsMapped++; if r.Passed { s.NISTPass++ } else { s.NISTFail++ } }
				if r.PCI != "" { s.PCIControlsMapped++; if r.Passed { s.PCIPass++ } else { s.PCIFail++ } }
			}
			if !r.Passed {
				s.TechnicalFindings++
			}
		}
		s.HygieneScore = 100
		s.HygieneLevel = "N/A"
		s.ResilienceScore = 100
		s.TopologyMermaid = "graph TD\n  Massive[Auditoría de Directorio Masivo]\n  style Massive fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc"
		return s
	}

	model := cfg.Model
	if model == "" { model = "No identificado en backup" }
	serial := cfg.Serial
	if serial == "" { serial = "No identificado en backup" }

	s := AuditCoverageSummary{
		Hostname:        cfg.Hostname,
		Model:           model,
		Serial:          serial,
		FirmwareVersion: cfg.Version,
		Build:           cfg.Build,
		AnalysisDate:    time.Now().Format("02 Jan 2006"),
		LinesProcessed:  cfg.LinesParsed,
		VDOMs:           cfg.VDOMs,
		VDOMCount:       len(cfg.VDOMs),
		HADetected:      cfg.HasHA,
		SDWANDetected:   cfg.HasSDWAN,
		FortiManagerDetected: cfg.HasFMG,
		SSLVPNDetected:  cfg.HasVPN,
	}

	if cfg.Root != nil {
		s.InterfaceCount = countEdits(cfg.Root, "system.interface")
		s.FirewallPolicyCount = countEdits(cfg.Root, "firewall.policy")
		s.AddressObjectCount = countEdits(cfg.Root, "firewall.address")
		s.AddressGroupCount = countEdits(cfg.Root, "firewall.addrgrp")
		s.ServiceObjectCount = countEdits(cfg.Root, "firewall.service.custom")
		s.ServiceGroupCount = countEdits(cfg.Root, "firewall.service.group")
		s.AdminUserCount = countEdits(cfg.Root, "system.admin")
		s.LocalInPolicyCount = countEdits(cfg.Root, "system.local-in-policy")
		s.VIPCount = countEdits(cfg.Root, "firewall.vip")
		s.IPPoolCount = countEdits(cfg.Root, "firewall.ippool")
		s.SSLVPNPortalCount = countEdits(cfg.Root, "vpn.ssl.web.portal")
		s.IPsecPhase1Count = countEdits(cfg.Root, "vpn.ipsec.phase1-interface")
		s.IPsecPhase2Count = countEdits(cfg.Root, "vpn.ipsec.phase2-interface")
		
		s.SecurityProfileCount = countEdits(cfg.Root, "firewall.profile-protocol-options") + 
			countEdits(cfg.Root, "firewall.ssl-ssh-profile") + 
			countEdits(cfg.Root, "firewall.av-profile") + 
			countEdits(cfg.Root, "firewall.ips-sensor")

		// Extract names of security profiles
		for _, path := range []string{"firewall.profile-protocol-options", "firewall.ssl-ssh-profile", "firewall.av-profile", "firewall.ips-sensor"} {
			nodes := cfg.Root.FindPath(path)
			for _, node := range nodes {
				for _, edit := range node.Children {
					if edit.Type == parser.NodeEdit {
						// Clean type name
						typeName := "Options"
						if strings.Contains(path, "ssl-ssh") {
							typeName = "SSL-Inspection"
						} else if strings.Contains(path, "av-profile") {
							typeName = "Antivirus"
						} else if strings.Contains(path, "ips-sensor") {
							typeName = "IPS"
						}
						s.SecurityProfilesList = append(s.SecurityProfilesList, fmt.Sprintf("%s (%s)", edit.Key, typeName))
					}
				}
			}
		}

		// Extract interfaces/VLANs
		nodes := cfg.Root.FindPath("system.interface")
		for _, node := range nodes {
			for _, edit := range node.Children {
				if edit.Type == parser.NodeEdit {
					vlanID := ""
					for _, setNode := range edit.Children {
						if setNode.Key == "vlanid" {
							vlanID = fmt.Sprintf(" | VLAN ID: %s", setNode.Value)
						}
					}
					s.VLANsList = append(s.VLANsList, fmt.Sprintf("%s%s", edit.Key, vlanID))
				}
			}
		}
	}

	// Calculate Hygiene Score
	hygieneScore := 100
	
	// CIS/Hardening Stats
	for _, r := range results {
		if r.Category == "HARDENING" {
			s.CISEvaluated++
			if r.Passed { s.CISPass++ } else { s.CISFail++ }
			
			if r.ISO27001 != "" { s.ISOControlsMapped++; if r.Passed { s.ISOPass++ } else { s.ISOFail++ } }
			if r.NIST != "" { s.NISTControlsMapped++; if r.Passed { s.NISTPass++ } else { s.NISTFail++ } }
			if r.PCI != "" { s.PCIControlsMapped++; if r.Passed { s.PCIPass++ } else { s.PCIFail++ } }
		}
		if !r.Passed { 
			s.TechnicalFindings++ 
			if r.Status == "CRÍTICO" { hygieneScore -= 5 } else if r.Status == "ALTO" { hygieneScore -= 3 }
		}
	}

	// Policy Risks (Aggregated)
	policyRisks := analyzePolicyRisks(cfg)
	for _, g := range policyRisks {
		switch g.GroupID {
		case "ANY_ANY_NO_LOG": s.PolicyAnyAnyCritical += g.AffectedCount; hygieneScore -= (g.AffectedCount * 10)
		case "SRC_ANY": s.PolicySrcAny += g.AffectedCount; hygieneScore -= (g.AffectedCount * 2)
		case "DST_ANY": s.PolicyDstAny += g.AffectedCount; hygieneScore -= (g.AffectedCount * 2)
		case "SERVICE_ALL": s.PolicyServiceAll += g.AffectedCount; hygieneScore -= (g.AffectedCount * 2)
		case "NO_LOGGING": s.PolicyNoLogging += g.AffectedCount; hygieneScore -= (g.AffectedCount * 1)
		}
	}

	if s.LocalInPolicyCount == 0 { hygieneScore -= 15 }
	
	if hygieneScore < 0 { hygieneScore = 0 }
	s.HygieneScore = hygieneScore
	if s.HygieneScore > 80 { s.HygieneLevel = "Excelente" } else if s.HygieneScore > 60 { s.HygieneLevel = "Bueno" } else if s.HygieneScore > 40 { s.HygieneLevel = "Regular" } else { s.HygieneLevel = "Pobre" }

	// PSIRT Stats
	s.PSIRTConsulted = len(enriched)
	for _, e := range enriched {
		s.PSIRTApplicable++
		if e.IsCisaKEV { s.PSIRTCisaKEV++ }
		if e.EPSSScore > 0 { s.PSIRTEPSSQueried++ }
		if e.EPSSScore > 0.1 { s.PSIRTEPSSHigh++ }
		if e.ExploitStatus == "Activo / Expuesto" || e.ExploitStatus == "exposición confirmada" {
			s.PSIRTExposureConfirmed++
		} else if e.ExploitStatus == "Mitigado por Configuración" {
			s.PSIRTNotApplicable++
		} else if e.ExploitStatus == "Revisión Manual" {
			s.PSIRTManualReview++
		} else {
			s.PSIRTVersionOnly++
		}
	}

	// Calidad Ejecutiva & Resiliencia (Pilar 4)
	s.ResilienceScore = CalculateResilienceScore(cfg)
	s.TopologyMermaid = GenerateMermaidTopology(cfg)

	return s
}

func countEdits(root *parser.ASTNode, path string) int {
	nodes := root.FindAllConfigs(path)
	count := 0
	for _, n := range nodes {
		for _, child := range n.Children {
			if child.Type == parser.NodeEdit {
				count++
			}
		}
	}
	return count
}

func mapSeverity(status string) string {
	switch status {
	case "CRÍTICO": return "CRÍTICO"
	case "ALTO": return "ALTO"
	case "MEDIO": return "MEDIO"
	default: return "BAJO"
	}
}

func extractUser(evidence string) string {
	parts := strings.Split(evidence, "system.admin.")
	if len(parts) > 1 {
		userPart := strings.Split(parts[1], ".")[0]
		return userPart
	}
	return ""
}

func enrichNarrative(g *FindingGroup) {
	if n, ok := executiveNarratives[g.GroupID]; ok {
		g.BusinessImpact = n.Impact
		g.Recommendation = n.Recommendation
	}
}

func analyzeHygiene(cfg *parser.FGTConfig) []FindingGroup {
	if cfg == nil || cfg.Root == nil { return nil }
	
	objects := cfg.Root.ExtractObjects()
	policies := cfg.Root.ExtractPolicies()
	
	// Crear mapa de uso
	usedNames := make(map[string]bool)
	for _, p := range policies {
		for _, a := range p.SrcAddr { usedNames[a] = true }
		for _, a := range p.DstAddr { usedNames[a] = true }
		for _, s := range p.Service { usedNames[s] = true }
	}
	
	orphanGroup := &FindingGroup{
		GroupID:        "HYG-OBJ-01",
		Title:          "objetos de red huérfanos (No utilizados)",
		Severity:       "BAJO",
		Category:       "HIGIENE",
		Summary:        "Direcciones y servicios definidos en la configuración que no están referenciados en ninguna política activa o inactiva.",
		BusinessImpact: executiveNarratives["HYG-OBJ-01"].Impact,
		Recommendation: executiveNarratives["HYG-OBJ-01"].Recommendation,
	}
	
	for _, obj := range objects {
		if !usedNames[obj.Name] && obj.Name != "all" && obj.Name != "ANY" && obj.Name != "ALL" {
			orphanGroup.AffectedCount++
			orphanGroup.AffectedItems = append(orphanGroup.AffectedItems, AffectedItem{
				Name:     obj.Name,
				Evidence: fmt.Sprintf("Tipo: %s | Nombre: %s", obj.Type, obj.Name),
				Line:     obj.Line,
			})
		}
	}
	
	if orphanGroup.AffectedCount > 0 {
		return []FindingGroup{*orphanGroup}
	}
	return nil
}

func analyzePolicyRisks(cfg *parser.FGTConfig) []FindingGroup {
	if cfg == nil || cfg.Root == nil { return nil }

	policies := cfg.Root.ExtractPolicies()
	riskGroups := make(map[string]*FindingGroup)
	
	for _, p := range policies {
		profile := evaluatePolicyRisk(p)
		if profile.RiskClass == "" { continue }

		group, ok := riskGroups[profile.RiskClass]
		if !ok {
			group = createFindingGroupForClass(profile.RiskClass)
			riskGroups[profile.RiskClass] = group
		}

		group.AffectedCount++
		evidence := fmt.Sprintf("src:%s dst:%s svc:%s action:%s log:%s", 
			strings.Join(p.SrcAddr, ","), strings.Join(p.DstAddr, ","), 
			strings.Join(p.Service, ","), p.Action, p.Logging)
		
		cliCmd := ""
		switch profile.RiskClass {
		case "ANY_ANY_NO_LOG":
			cliCmd = fmt.Sprintf("config firewall policy\n  edit %s\n    set logtraffic all\n    # RECOMENDACIÓN CRÍTICA: Restringir 'all'\n    set srcaddr [ORIGEN_SEGURO]\n    set dstaddr [DESTINO_SEGURO]\n    set service [PUERTOS_ESPECÍFICOS]\nend", p.ID)
		case "ANY_ANY_WITH_LOG":
			cliCmd = fmt.Sprintf("config firewall policy\n  edit %s\n    # RECOMENDACIÓN ALTA: Restringir 'all'\n    set srcaddr [ORIGEN_SEGURO]\n    set dstaddr [DESTINO_SEGURO]\n    set service [PUERTOS_ESPECÍFICOS]\nend", p.ID)
		case "SRC_ANY":
			cliCmd = fmt.Sprintf("config firewall policy\n  edit %s\n    # RECOMENDACIÓN: Reemplazar origen 'all'\n    set srcaddr [ORIGEN_SEGURO]\nend", p.ID)
		case "DST_ANY":
			cliCmd = fmt.Sprintf("config firewall policy\n  edit %s\n    # RECOMENDACIÓN: Reemplazar destino 'all'\n    set dstaddr [DESTINO_SEGURO]\nend", p.ID)
		case "SERVICE_ALL":
			cliCmd = fmt.Sprintf("config firewall policy\n  edit %s\n    # RECOMENDACIÓN: Reemplazar servicio 'ALL'\n    set service [PUERTOS_ESPECÍFICOS]\nend", p.ID)
		case "NO_LOGGING":
			cliCmd = fmt.Sprintf("config firewall policy\n  edit %s\n    set logtraffic all\nend", p.ID)
		case "DISABLED_RISK":
			cliCmd = fmt.Sprintf("config firewall policy\n  delete %s\nend", p.ID)
		}

		group.AffectedItems = append(group.AffectedItems, AffectedItem{
			PolicyID:       p.ID,
			VDOM:           p.VDOM,
			Name:           p.Name,
			Evidence:       evidence,
			RemediationCLI: cliCmd,
		})
	}

	var result []FindingGroup
	for _, g := range riskGroups {
		if g.AffectedCount > 0 {
			result = append(result, *g)
		}
	}
	return result
}

func evaluatePolicyRisk(p parser.FirewallPolicy) PolicyRiskProfile {
	profile := PolicyRiskProfile{
		PolicyID: p.ID,
		VDOM:     p.VDOM,
	}

	isSrcAll := containsAll(p.SrcAddr)
	isDstAll := containsAll(p.DstAddr)
	isSvcAll := containsAll(p.Service)
	isActionAccept := p.Action == "accept"
	isLogDisabled := p.Logging == "" || p.Logging == "disable"
	isEnabled := p.Status != "disable"

	score := 0
	if isSrcAll && isDstAll { score += 40 }
	if isSvcAll { score += 25 }
	if isLogDisabled { score += 20 }
	if isEnabled { score += 20 }
	if p.Status == "disable" { score -= 40 }

	profile.RiskScore = score

	if isEnabled {
		if isSrcAll && isDstAll && isSvcAll && isActionAccept && isLogDisabled {
			profile.RiskClass = "ANY_ANY_NO_LOG"
		} else if isSrcAll && isDstAll && isSvcAll && isActionAccept {
			profile.RiskClass = "ANY_ANY_WITH_LOG"
		} else if isSrcAll {
			profile.RiskClass = "SRC_ANY"
		} else if isDstAll {
			profile.RiskClass = "DST_ANY"
		} else if isSvcAll {
			profile.RiskClass = "SERVICE_ALL"
		} else if isLogDisabled && isActionAccept {
			profile.RiskClass = "NO_LOGGING"
		}
	} else if score > 30 {
		profile.RiskClass = "DISABLED_RISK"
	}

	return profile
}

func containsAll(list []string) bool {
	for _, s := range list {
		low := strings.ToLower(s)
		if low == "all" || low == "any" { return true }
	}
	return false
}

func createFindingGroupForClass(class string) *FindingGroup {
	g := &FindingGroup{GroupID: class, Category: "FW-INTEL"}
	switch class {
	case "ANY_ANY_NO_LOG":
		g.Title = "políticas any-any críticas activas sin logging"
		g.Severity = "CRÍTICO"
		g.Summary = "Reglas que permiten tráfico total sin dejar rastro en los registros."
		g.BusinessImpact = "Permiten el movimiento lateral indetectable y la exfiltración masiva de datos."
		g.Recommendation = "Restringir origen, destino y servicios. Habilitar logtraffic=all inmediatamente."
	case "ANY_ANY_WITH_LOG":
		g.Title = "políticas any-any activas (con visibilidad)"
		g.Severity = "ALTO"
		g.Summary = "Reglas excesivamente permisivas que permiten cualquier tráfico."
		g.BusinessImpact = "Aumentan drásticamente la superficie de ataque interna y externa."
		g.Recommendation = "Segmentar la red y usar objetos de dirección específicos."
	case "SRC_ANY":
		g.Title = "políticas con origen no restringido (all)"
		g.Severity = "MEDIO"
		g.Summary = "Cualquier host puede iniciar conexiones hacia los destinos definidos."
		g.BusinessImpact = "Riesgo de acceso no autorizado desde cualquier punto de la red."
		g.Recommendation = "Limitar los segmentos de red permitidos como origen."
	case "DST_ANY":
		g.Title = "políticas con destino no restringido (all)"
		g.Severity = "MEDIO"
		g.Summary = "El tráfico puede alcanzar cualquier red externa o interna."
		g.BusinessImpact = "Facilita la exfiltración de datos y conexiones a C2 externos."
		g.Recommendation = "Usar categorías de URL o grupos de direcciones IP confiables."
	case "SERVICE_ALL":
		g.Title = "políticas con servicios no restringidos (ALL)"
		g.Severity = "MEDIO"
		g.Summary = "Se permite cualquier puerto y protocolo en esta regla."
		g.BusinessImpact = "Permite el uso de protocolos inseguros o túneles no autorizados."
		g.Recommendation = "Definir específicamente los puertos necesarios (ej. HTTPS, DNS)."
	case "NO_LOGGING":
		g.Title = "políticas activas sin visibilidad (Logging deshabilitado)"
		g.Severity = "BAJO"
		g.Summary = "El tráfico que fluye por estas reglas no genera registros."
		g.BusinessImpact = "Impide el análisis forense y la detección de incidentes."
		g.Recommendation = "Configurar 'set logtraffic all' en todas las reglas."
	case "DISABLED_RISK":
		g.Title = "políticas riesgosas actualmente deshabilitadas"
		g.Severity = "BAJO"
		g.Summary = "Reglas con configuraciones inseguras que están inactivas."
		g.BusinessImpact = "Representan una deuda técnica de seguridad y riesgo si se habilitan."
		g.Recommendation = "Eliminar reglas obsoletas para mantener la higiene."
	default:
		g.Title = "Riesgo de configuración"
	}
	return g
}

func CalculateResilienceScore(cfg *parser.FGTConfig) int {
	if cfg == nil || cfg.Root == nil { return 0 }
	score := 0
	
	// 1. Redundancia de Enlaces (SD-WAN) - Max 25 puntos
	if cfg.HasSDWAN {
		score += 25
	} else {
		wanCount := 0
		intfNodes := cfg.Root.FindPath("system.interface")
		for _, intfNode := range intfNodes {
			for _, editNode := range intfNode.Children {
				lowName := strings.ToLower(editNode.Key)
				role := ""
				for _, setNode := range editNode.Children {
					if setNode.Key == "role" {
						role = strings.ToLower(setNode.Value)
					}
				}
				if strings.Contains(lowName, "wan") || role == "wan" {
					wanCount++
				}
			}
		}
		if wanCount > 1 {
			score += 15
		} else if wanCount == 1 {
			score += 5
		}
	}

	// 2. Alta Disponibilidad (HA) - Max 25 puntos
	haNodes := cfg.Root.FindPath("system.ha")
	hasHA := false
	for _, haNode := range haNodes {
		for _, child := range haNode.Children {
			if child.Key == "status" && child.Value != "disable" {
				hasHA = true
			}
		}
	}
	if hasHA || cfg.HasHA {
		score += 25
	}

	// 3. Centralización de Logs - Max 25 puntos
	hasAnalyzer := false
	faNodes := cfg.Root.FindPath("system.fortianalyzer.setting")
	for _, faNode := range faNodes {
		for _, child := range faNode.Children {
			if child.Key == "status" && child.Value == "enable" {
				hasAnalyzer = true
			}
		}
	}
	syslogNodes := cfg.Root.FindPath("system.syslogd.setting")
	hasSyslog := false
	for _, sNode := range syslogNodes {
		for _, child := range sNode.Children {
			if child.Key == "status" && child.Value == "enable" {
				hasSyslog = true
			}
		}
	}
	if hasAnalyzer || hasSyslog || cfg.HasFMG {
		score += 25
	} else {
		score += 5
	}

	// 4. Copias de Respaldo Automatizadas - Max 25 puntos
	hasAutoBackup := false
	abNodes := cfg.Root.FindPath("system.auto-backup")
	for _, abNode := range abNodes {
		for _, child := range abNode.Children {
			if child.Key == "status" && child.Value == "enable" {
				hasAutoBackup = true
			}
		}
	}
	if hasAutoBackup {
		score += 25
	}

	return score
}

func sanitizeNodeID(id string) string {
	var sb strings.Builder
	for _, r := range id {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('_')
		}
	}
	return sb.String()
}

// SEC-FIX VULN-002: Sanitizar etiquetas de Mermaid para prevenir inyección HTML/XSS
// Los datos provienen de archivos .conf potencialmente manipulados por atacantes
func sanitizeMermaidLabel(input string) string {
	replacer := strings.NewReplacer(
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&#39;",
		"&", "&amp;",
		"\n", " ",
		"\r", "",
	)
	return replacer.Replace(input)
}

func GenerateMermaidTopology(cfg *parser.FGTConfig) string {
	if cfg == nil || cfg.Root == nil {
		return "graph LR\n    A[Configuración Vacía]"
	}

	// 1. Identificar Interfaces Activas a través de Políticas y Enrutamiento Estático
	activeIntfs := make(map[string]bool)
	policies := cfg.Root.ExtractPolicies()
	for _, p := range policies {
		if p.Status != "disable" && p.Action == "accept" {
			for _, src := range p.SrcIntf {
				activeIntfs[src] = true
			}
			for _, dst := range p.DstIntf {
				activeIntfs[dst] = true
			}
		}
	}

	staticRouteNodes := cfg.Root.FindPath("router.static")
	for _, rNode := range staticRouteNodes {
		for _, editNode := range rNode.Children {
			for _, setNode := range editNode.Children {
				if setNode.Key == "device" {
					activeIntfs[strings.Trim(setNode.Value, "\"")] = true
				}
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("graph LR\n")
	sb.WriteString("    %% Clases de Estilos Premium B2B\n")
	sb.WriteString("    classDef internet fill:#1e1b4b,stroke:#ef4444,stroke-width:2px,color:#fca5a5;\n")
	sb.WriteString("    classDef lan fill:#172554,stroke:#3b82f6,stroke-width:2px,color:#93c5fd;\n")
	sb.WriteString("    classDef dmz fill:#451a03,stroke:#f59e0b,stroke-width:2px,color:#fde047;\n")
	sb.WriteString("    classDef vdom fill:#1e1b4b,stroke:#8b5cf6,stroke-width:3px,color:#d8b4fe;\n")
	sb.WriteString("    classDef vpn fill:#042f2e,stroke:#14b8a6,stroke-width:2px,color:#99f6e4;\n")
	sb.WriteString("    classDef default fill:#0f172a,stroke:#475569,stroke-width:1px,color:#94a3b8;\n\n")

	sb.WriteString("    Internet((\"🌐 Internet Pública\")):::internet\n")
	sb.WriteString("    IntNet((\"💻 Red Interna (LAN)\")):::lan\n")
	sb.WriteString("    DMZNet((\"🛡️ Zona DMZ\")):::dmz\n\n")

	intfNodes := cfg.Root.FindPath("system.interface")
	intfs := make(map[string]string)
	intfVDOM := make(map[string]string)
	vdomIntfs := make(map[string][]string)
	
	model := cfg.Model
	if model == "" { model = "FortiGate" }

	for _, intfNode := range intfNodes {
		for _, editNode := range intfNode.Children {
			if editNode.Type == parser.NodeEdit {
				name := editNode.Key
				role := "default"
				vdom := editNode.VDOM
				if vdom == "" { vdom = "root" }
				
				for _, setNode := range editNode.Children {
					if setNode.Key == "role" {
						role = strings.Trim(strings.ToLower(setNode.Value), "\"")
					}
				}

				// Incluir interfaces activas, físicas principales o configuradas con roles específicos
				lowName := strings.ToLower(name)
				isPrimaryWAN := lowName == "wan" || lowName == "wan1" || lowName == "wan2" || lowName == "a"
				isPrimaryLAN := lowName == "internal" || lowName == "lan"
				isVPN := strings.Contains(lowName, "ssl") || strings.Contains(lowName, "vpn") || strings.Contains(lowName, "ipsec")
				
				if activeIntfs[name] || isPrimaryWAN || isPrimaryLAN || isVPN || role == "wan" || role == "lan" || role == "dmz" {
					intfs[name] = role
					intfVDOM[name] = vdom
					vdomIntfs[vdom] = append(vdomIntfs[vdom], name)
				}
			}
		}
	}

	for vdom, names := range vdomIntfs {
		sb.WriteString(fmt.Sprintf("    subgraph VDOM_%s [\"🔒 VDOM: %s\"]\n", sanitizeNodeID(vdom), sanitizeMermaidLabel(vdom)))
		
		// Nodo central del chasis FortiGate dentro de la VDOM
		fgtID := fmt.Sprintf("FGT_%s", sanitizeNodeID(vdom))
		sb.WriteString(fmt.Sprintf("        %s[\"🛡️ FortiGate Firewall<br/><small style='opacity:0.9;font-size:10px;'>Modelo: %s</small>\"]:::vdom\n", fgtID, sanitizeMermaidLabel(model)))

		for _, name := range names {
			role := intfs[name]
			lowName := strings.ToLower(name)
			isWAN := strings.Contains(lowName, "wan") || role == "wan" || lowName == "a"
			isLAN := strings.Contains(lowName, "lan") || role == "lan" || lowName == "internal"
			isDMZ := strings.Contains(lowName, "dmz") || role == "dmz"
			isVPN := strings.Contains(lowName, "ssl") || strings.Contains(lowName, "vpn") || strings.Contains(lowName, "ipsec")

			icon := "⚙️"
			class := "default"
			if isVPN {
				icon = "🔒"
				class = "vpn"
			} else if isWAN {
				icon = "🌐"
				class = "internet"
			} else if isLAN {
				icon = "💻"
				class = "lan"
			} else if isDMZ {
				icon = "🛡️"
				class = "dmz"
			}
			
			cleanName := sanitizeNodeID(name)
			sb.WriteString(fmt.Sprintf("        %s[\"%s %s <br/> <small style='opacity:0.6;font-size:9px;'>role: %s</small>\"]:::%s\n", cleanName, icon, sanitizeMermaidLabel(name), sanitizeMermaidLabel(role), class))
			
			// Para evitar espagueti de líneas: solo las interfaces físicas principales y VPN conectan al chasis
			isSubInterface := strings.Contains(lowName, ".") || strings.Contains(lowName, "vlan") || strings.Contains(lowName, " ")
			if !isSubInterface || isVPN {
				sb.WriteString(fmt.Sprintf("        %s --- %s\n", fgtID, cleanName))
			}
		}
		sb.WriteString("    end\n\n")
		sb.WriteString(fmt.Sprintf("    style VDOM_%s fill:#070a13,stroke:#8b5cf6,stroke-width:2px,stroke-dasharray: 5 5;\n", sanitizeNodeID(vdom)))
	}

	for name, role := range intfs {
		lowName := strings.ToLower(name)
		isWAN := strings.Contains(lowName, "wan") || role == "wan" || lowName == "a"
		isLAN := strings.Contains(lowName, "lan") || role == "lan" || lowName == "internal"
		isDMZ := strings.Contains(lowName, "dmz") || role == "dmz"

		// Para evitar espagueti: solo interfaces físicas principales conectan a las nubes externas
		isSubInterface := strings.Contains(lowName, ".") || strings.Contains(lowName, "vlan") || strings.Contains(lowName, " ")
		if !isSubInterface {
			cleanName := sanitizeNodeID(name)
			if isWAN {
				sb.WriteString(fmt.Sprintf("    %s -.-> Internet\n", cleanName))
			} else if isLAN {
				sb.WriteString(fmt.Sprintf("    %s -.-> IntNet\n", cleanName))
			} else if isDMZ {
				sb.WriteString(fmt.Sprintf("    %s -.-> DMZNet\n", cleanName))
			}
		}
	}

	// Trazar flujos de políticas activas entre puertos activos
	flowCount := 0
	for _, p := range policies {
		if p.Status != "disable" && p.Action == "accept" && flowCount < 12 {
			for _, src := range p.SrcIntf {
				for _, dst := range p.DstIntf {
					if _, srcOk := intfs[src]; srcOk {
						if _, dstOk := intfs[dst]; dstOk {
							sb.WriteString(fmt.Sprintf("    %s ==>|\"⚡ Regla %s\"| %s\n", sanitizeNodeID(src), p.ID, sanitizeNodeID(dst)))
							flowCount++
						}
					}
				}
			}
		}
	}


	return sb.String()
}

