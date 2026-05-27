package matcher

import (
	"strings"
	"tricera/internal/intelligence"
	"tricera/internal/parser"
)

// CheckExposure busca evidencia en la configuración de que un advisory es aplicable
func CheckExposure(advisory intelligence.Advisory, config *parser.FGTConfig) intelligence.FindingState {
	title := strings.ToUpper(advisory.Title)
	desc := strings.ToUpper(advisory.Description)
	
	// Si el advisory es de kernel o CLI, requiere revisión manual por definición
	if strings.Contains(title, "KERNEL") || strings.Contains(title, "CLI") || strings.Contains(title, "GUI") ||
		strings.Contains(desc, "KERNEL") || strings.Contains(desc, "COMMAND LINE") {
		return intelligence.ManualReviewRequired
	}

	// Mapeo de Componentes a Rutas de Configuración
	exposureMap := map[string][]string{
		"SSL-VPN":  {"vpn.ssl.settings"},
		"SSLVPN":   {"vpn.ssl.settings"},
		"IPSEC":    {"vpn.ipsec.phase1-interface"},
		"CAPWAP":   {"wireless-controller", "system.global.switch-controller"},
		"WIFI":     {"wireless-controller"},
		"FORTIAP":  {"wireless-controller"},
		"BGP":      {"router.bgp"},
		"OSPF":     {"router.ospf"},
		"SNMP":     {"system.snmp"},
		"ZTNA":     {"firewall.access-proxy", "firewall.proxy-policy"},
		"HTTPS":    {"system.global.admin-sport"},
		"FGFM":     {"system.central-management"},
		"LDAP":     {"user.ldap"},
		"RADIUS":   {"user.radius"},
		"FSSO":     {"user.fsso"},
		"WEB":      {"webfilter"},
	}

	foundComponent := false
	for kw, paths := range exposureMap {
		if strings.Contains(title, kw) || strings.Contains(desc, kw) || strings.Contains(strings.ToUpper(advisory.Component), kw) {
			foundComponent = true
			for _, path := range paths {
				nodes := config.Root.FindPath(path)
				if len(nodes) > 0 {
					return intelligence.ExposureConfirmed
				}
			}
		}
	}

	if foundComponent {
		return intelligence.NotApplicableByConfig
	}

	return intelligence.NoConfigEvidence
}
