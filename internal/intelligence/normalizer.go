package intelligence

import (
	"strings"
)

// NormalizeAdvisory limpia, estandariza e infiere campos de un advisory
func NormalizeAdvisory(adv *Advisory) {
	adv.ID = strings.TrimSpace(adv.ID)
	adv.Title = strings.TrimSpace(adv.Title)
	adv.Severity = strings.TrimSpace(adv.Severity)
	
	// Inferir componente si está vacío
	if adv.Component == "" {
		adv.Component = InferComponent(adv.Title)
	}

	// Normalizar Severidad a Español
	// SEC-FIX VULN-011: Severidades desconocidas se mapean a 'Alta' para no subestimar riesgos
	switch strings.ToLower(adv.Severity) {
	case "critical": adv.Severity = "Crítica"
	case "high":     adv.Severity = "Alta"
	case "medium":   adv.Severity = "Media"
	case "low":      adv.Severity = "Baja"
	case "":         adv.Severity = "Media"
	default:         adv.Severity = "Alta"
	}

	// Limpiar CVEs
	for i, cve := range adv.CVEs {
		adv.CVEs[i] = strings.TrimSpace(cve)
	}
}

func InferComponent(title string) string {
	title = strings.ToUpper(title)
	if strings.Contains(title, "SSL-VPN") || strings.Contains(title, "SSL VPN") { return "SSL-VPN" }
	if strings.Contains(title, "CAPWAP") { return "CAPWAP" }
	if strings.Contains(title, "ZTNA") { return "ZTNA" }
	if strings.Contains(title, "WEB FILTER") { return "Web Filter" }
	if strings.Contains(title, "CLI") { return "CLI" }
	if strings.Contains(title, "FORTICLOUD SSO") { return "FortiCloud SSO / GUI" }
	if strings.Contains(title, "LDAP") { return "LDAP" }
	if strings.Contains(title, "FSSO") { return "FSSO" }
	if strings.Contains(title, "SSH") { return "SSH" }
	if strings.Contains(title, "KERNEL") { return "Kernel" }
	if strings.Contains(title, "REQUEST SMUGGLING") { return "HTTP Parser / Web interface" }
	if strings.Contains(title, "GUI") { return "Web GUI" }
	if strings.Contains(title, "IPSEC") { return "IPsec VPN" }
	return "No especificado por fuente"
}
