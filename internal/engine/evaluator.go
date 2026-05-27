package engine

import (
	"fmt"
	"regexp"
	"strings"
	"tricera/internal/parser"
	"tricera/internal/remediator"
)

// SEC-FIX B-03: Regex con límites de palabra para evitar falsos positivos (ej. 2100 vs 21)
var insecureSvcRegex = regexp.MustCompile(`(?i)\b(rdp|ftp|telnet|ldap|smb|21|23|389|3389)\b`)

type CheckResult struct {
	ID              string `json:"id"`
	Title           string `json:"title"`
	Status          string `json:"status"`
	Evidence        string `json:"evidence"`
	Remediation     string `json:"remediation"`
	Workaround      string `json:"workaround"`
	Reference       string `json:"reference"`
	Category        string `json:"category"`
	Passed          bool   `json:"passed"`
	FailedPath      string `json:"failed_path"`
	CLIScript       string `json:"cli_script"`
	DeviceName      string `json:"device_name"`
	ImpactLevel     string `json:"impact_level"`
	Section         string `json:"section"`
	VDOM            string `json:"vdom"`
	MitreID         string `json:"mitre_id"`
	IsExploited     bool   `json:"is_exploited"`
	ThreatSource    string `json:"threat_source"`
	Line            int    `json:"line"`
	Value           string `json:"value"`
	BusinessImpact  string `json:"business_impact"`
	TechnicalImpact string `json:"technical_impact"`
	ValidationStep  string `json:"validation_step"`
	ISO27001        string `json:"iso27001"`
	NIST            string `json:"nist"`
	PCI             string `json:"pci"`
	QuickFix        string `json:"quick_fix"`
}

var requiredPaths = []string{"system.global"}

func Evaluate(deviceName string, deviceVer string, config *parser.FGTConfig, rule Rule, debug bool) []CheckResult {
	var results []CheckResult
	if rule.AffectedVersion != "" && deviceVer != "" && deviceVer != "desconocido" {
		if !IsVersionVulnerable(deviceVer, rule.AffectedVersion) { return nil }
	}

	nodes := config.Root.FindPath(rule.TriggerPath)
	for _, node := range nodes {
		isVulnerable := checkTrigger(rule.Operator, node.Value, rule.TriggerValue)
		foundPath := node.GetPath()
		
		// SEC-FIX: Evitar falsos positivos en Ping / ICMP de interfaces LAN
		if rule.ID == "CIS-FGT-20" {
			parts := strings.Split(foundPath, ".")
			if len(parts) >= 3 {
				intfName := parts[2]
				intfLower := strings.ToLower(intfName)
				
				// Buscar el rol
				role := ""
				intfNodes := config.Root.FindPath(fmt.Sprintf("system.interface.%s.role", intfName))
				if len(intfNodes) > 0 {
					role = strings.Trim(strings.ToLower(intfNodes[0].Value), "\"")
				}
				
				isWAN := strings.Contains(intfLower, "wan") || role == "wan" || intfLower == "a"
				if !isWAN {
					// Omitir si no es una interfaz WAN externa
					continue
				}
			}
		}

		status := mapImpact(rule.ImpactLevel)
		passed := true
		evidence := fmt.Sprintf("[%s] Valor seguro: %s = %s", deviceName, foundPath, node.Value)
		cli := ""

		if isVulnerable {
			passed = false
			evidence = fmt.Sprintf("[%s] RIESGO DETECTADO en línea %d: %s = %s", deviceName, node.Line, foundPath, node.Value)
			cli = remediator.GenerateCLI(config.Root, foundPath, rule.RemediationValue)
		}

		results = append(results, CheckResult{
			DeviceName: deviceName, ID: rule.ID, Title: rule.Title, Status: status, Passed: passed, Evidence: evidence,
			Remediation: rule.Remediation, Workaround: rule.Workaround, Reference: rule.Reference, Category: rule.Category,
			CLIScript: cli, ImpactLevel: rule.ImpactLevel, Section: rule.Section, VDOM: node.VDOM, FailedPath: foundPath,
			MitreID: rule.MitreID,
			IsExploited: rule.IsExploited, ThreatSource: rule.ThreatSource, Line: node.Line, Value: node.Value,
			BusinessImpact: rule.BusinessImpact, TechnicalImpact: rule.TechnicalImpact, ValidationStep: rule.ValidationStep,
			ISO27001: rule.ISO27001, NIST: rule.NIST, PCI: rule.PCI,
			QuickFix: rule.QuickFix,
		})
	}

	if len(nodes) == 0 {
		if rule.Category == "HARDENING" {
			evidence := fmt.Sprintf("CONTROL AUSENTE: La ruta '%s' no está configurada.", rule.TriggerPath)
			
			switch rule.ID {
			case "CIS-FGT-25":
				evidence = "RESPALDO AUTOMÁTICO INACTIVO: El respaldo automático de la configuración no está configurado en el sistema global. Para prevenir que en un futuro se transmita en texto plano vía FTP (el cual está ausente pero expone un riesgo potencial), se debe configurar explícitamente forzando SFTP o HTTPS."
			case "CIS-FGT-09":
				evidence = "RIESGO DE SEGURIDAD FÍSICA ACTIVO: El parámetro 'usb-firmware-upgrade' no está configurado en el archivo. En FortiOS, la ausencia de esta directiva significa que el valor predeterminado ('enable') de fábrica está ACTIVO, permitiendo la carga y actualización local de firmware vía USB sin restricciones de red."
			case "CIS-FGT-03":
				evidence = "BANNER DE ADVERTENCIA INACTIVO: El banner de advertencia pre-autenticación ('pre-login-banner') no está configurado en el archivo global. Legalmente se encuentra deshabilitado por defecto de fábrica."
			case "CIS-FGT-02":
				evidence = "POLÍTICA DE CONTRASEÑAS DÉBIL: La directiva global 'system.password-policy' no está definida en la configuración, lo que permite el uso de credenciales locales débiles sin restricción de complejidad o longitud mínima de caracteres."
			case "CIS-FGT-06":
				evidence = "LOGGING LOCAL SIN RESPALDO EXTERNO: El envío de registros hacia FortiAnalyzer o SIEM externo no está configurado ('fortianalyzer.setting' ausente). En caso de un ataque destructivo o de ransomware, los logs locales serán eliminados, dejando al equipo forense sin rastro del compromiso."
			case "CIS-FGT-27":
				evidence = "INSPECCIÓN DE CONTENIDO DESHABILITADA (NO UTM): No se han configurado perfiles de seguridad activos (antivirus, ips, etc.) en las políticas aceptadas generales ('utm-status' ausente o deshabilitado), permitiendo el paso de tráfico sin inspección profunda de capa 7."
			}

			return []CheckResult{{
				DeviceName: deviceName, ID: rule.ID, Title: rule.Title, Status: mapImpact(rule.ImpactLevel), Passed: false,
				Evidence: evidence,
				Remediation: rule.Remediation, Category: rule.Category, Section: rule.Section, BusinessImpact: rule.BusinessImpact,
				TechnicalImpact: rule.TechnicalImpact, ValidationStep: rule.ValidationStep,
				ISO27001: rule.ISO27001, NIST: rule.NIST, PCI: rule.PCI, QuickFix: rule.QuickFix,
			}}
		}
		return []CheckResult{{
			DeviceName: deviceName, ID: rule.ID, Title: rule.Title, Status: "NO VERIFICADO", Passed: true,
			Evidence: fmt.Sprintf("No se detectó el servicio o la configuración activa para '%s'.", rule.TriggerPath),
			Category: rule.Category,
		}}
	}
	return results
}

func mapImpact(level string) string {
	switch level {
	case "C": return "CRÍTICO"
	case "H": return "ALTO"
	case "M": return "MEDIO"
	case "L": return "BAJO"
	default: return "ALTO"
	}
}

func AnalyzeFirewallIntelligence(deviceName string, cfg *parser.FGTConfig) []CheckResult {
	var results []CheckResult
	
	// A. Auditoría Dinámica de Ciclo de Vida del Hardware (EOL)
	if cfg.Model != "" {
		modelUpper := strings.ToUpper(cfg.Model)
		// Modelos descontinuados o limitados D/E (ej. 30D, 60D, 100D, 30E, 50E, etc.)
		isLegacyD := strings.Contains(modelUpper, "30D") || strings.Contains(modelUpper, "60D") || strings.Contains(modelUpper, "90D") || strings.Contains(modelUpper, "100D") || strings.HasSuffix(modelUpper, "D")
		isLegacyE := strings.Contains(modelUpper, "30E") || strings.Contains(modelUpper, "50E") || strings.Contains(modelUpper, "80E") || strings.HasSuffix(modelUpper, "E")
		
		if isLegacyD || isLegacyE {
			results = append(results, CheckResult{
				DeviceName: deviceName, ID: "INT-HW-EOL", Status: "CRÍTICO", Category: "INTELLIGENCE", Section: "SYS",
				Title: "Hardware de Firewall Descontinuado / End-of-Life (EOL)", MitreID: "T1190",
				Evidence: fmt.Sprintf("El modelo de hardware detectado '%s' es una plataforma antigua que ha alcanzado su Fin de Vida (EOL) y no soporta actualizaciones modernas de seguridad.", cfg.Model),
				BusinessImpact: "Operar hardware EOL deja la organización vulnerable a fallos físicos sin reemplazo de garantía (RMA) y a fallos de seguridad críticos ya que no soporta firmwares modernos de FortiOS.",
				TechnicalImpact: "Imposibilidad física de actualizar el sistema operativo del firewall a ramas seguras soportadas.",
				Remediation: "Planificar la sustitución tecnológica (Tech Refresh) del dispositivo por un modelo actual equivalente (ej. serie F o G).",
			})
		}
	}

	// 1. Shadow & Permissive Rules Analysis
	policies := cfg.Root.ExtractPolicies()
	vdomPolicies := make(map[string][]parser.FirewallPolicy)
	for _, p := range policies {
		vdomPolicies[p.VDOM] = append(vdomPolicies[p.VDOM], p)
	}

	for vdom, pols := range vdomPolicies {
		for i := 0; i < len(pols); i++ {
			p := pols[i]
			nameStr := p.Name
			if nameStr == "" {
				nameStr = "Sin Nombre"
			}
			
			// B. Detección Inteligente de Regla Any-Any-Any ACCEPT (Bypass de Seguridad)
			if p.Status != "disable" && strings.ToLower(p.Action) == "accept" && containsAll(p.SrcAddr) && containsAll(p.DstAddr) && containsAll(p.Service) {
				results = append(results, CheckResult{
					DeviceName: deviceName, ID: "INT-BYPASS-01", Status: "CRÍTICO", Category: "INTELLIGENCE", Section: "SEC",
					Title: "Política Any-Any-Any ACCEPT Altamente Permisiva", VDOM: vdom, Line: p.Line, MitreID: "T1562.001",
					FailedPath: p.ID,
					Evidence: fmt.Sprintf("La política ID %s ('%s') en VDOM %s permite cualquier origen, cualquier destino y todos los servicios con la acción ACCEPT.", p.ID, nameStr, vdom),
					BusinessImpact: "Anula por completo el propósito del firewall de segmentar la red. Permite la libre propagación de ataques y malware lateralmente sin restricciones.",
					TechnicalImpact: "Apertura completa de todos los puertos TCP/UDP de origen a destino en el plano de datos.",
					Remediation: "Restringir el origen, destino o puertos específicos de esta política. Limitar la regla aplicando el principio de mínimo privilegio.",
				})
			}

			// C. Detección de Servicios Inseguros / No Cifrados en Reglas Activas (RDP, FTP, Telnet, LDAP, SMB)
			if p.Status != "disable" && strings.ToLower(p.Action) == "accept" {
				for _, svc := range p.Service {
					if insecureSvcRegex.MatchString(svc) {
						results = append(results, CheckResult{
							DeviceName: deviceName, ID: "INT-SVC-INSECURE", Status: "ALTO", Category: "INTELLIGENCE", Section: "SEC",
							Title: "Exposición de Servicio Inseguro / Protocolo No Cifrado", VDOM: vdom, Line: p.Line, MitreID: "T1021",
							FailedPath: p.ID,
							Evidence: fmt.Sprintf("La política ID %s ('%s') permite el servicio vulnerable o no cifrado '%s' con la acción ACCEPT.", p.ID, nameStr, svc),
							BusinessImpact: "Permitir protocolos no cifrados o altamente explotables (como RDP directo, FTP, LDAP o SMB) expone la red interna a interceptación de credenciales en tránsito y ataques de penetración directa.",
							TechnicalImpact: "Transmisión de datos sensibles sin cifrado fuerte y exposición perimetral de vectores de ataque conocidos.",
							Remediation: "Migrar a alternativas seguras: usar VPN IPsec/SSL para accesos de escritorio remoto (RDP), SFTP para archivos, LDAPS (cifrado) para directorio y SSH para administración.",
						})
					}
				}
			}

			// D. Segmentación Insegura: Exposición Directa de DMZ a LAN
			if p.Status != "disable" && strings.ToLower(p.Action) == "accept" {
				isSrcDMZ := false
				isDstLAN := false
				for _, si := range p.SrcIntf {
					low := strings.ToLower(si)
					if strings.Contains(low, "dmz") {
						isSrcDMZ = true
					}
				}
				for _, di := range p.DstIntf {
					low := strings.ToLower(di)
					if strings.Contains(low, "lan") || strings.Contains(low, "internal") {
						isDstLAN = true
					}
				}
				if isSrcDMZ && isDstLAN {
					if containsAll(p.Service) || len(p.Service) > 3 {
						results = append(results, CheckResult{
							DeviceName: deviceName, ID: "INT-DMZ-EXPOSED", Status: "ALTO", Category: "INTELLIGENCE", Section: "SEC",
							Title: "Segmentación Insegura: Exposición de DMZ a LAN", VDOM: vdom, Line: p.Line, MitreID: "T1021",
							FailedPath: p.ID,
							Evidence: fmt.Sprintf("La política ID %s ('%s') permite la comunicación directa de la zona pública/semipública DMZ (%s) hacia la red interna LAN (%s) de forma muy permisiva.", p.ID, nameStr, strings.Join(p.SrcIntf, ","), strings.Join(p.DstIntf, ",")),
							BusinessImpact: "La DMZ aloja servicios expuestos a internet (ej. servidores web). Si uno de estos servidores es vulnerado y existe una regla permisiva hacia la LAN, el atacante tomará control de la red interna corporativa de inmediato.",
							TechnicalImpact: "Falta de aislamiento y zonificación de seguridad rigurosa (zoning bypass).",
							Remediation: "Restringir la regla para permitir únicamente flujos estrictamente necesarios hacia IPs internas específicas y puertos exactos, habilitando perfiles IPS y antivirus rigurosos.",
						})
					}
				}
			}

			for j := i + 1; j < len(pols); j++ {
				if isShadowed(pols[i], pols[j]) {
					nameInferior := pols[j].Name
					if nameInferior == "" {
						nameInferior = "Sin Nombre"
					}
					nameSuperior := pols[i].Name
					if nameSuperior == "" {
						nameSuperior = "Sin Nombre"
					}
					
					evidenceText := fmt.Sprintf("Regla Inalcanzable: La política inferior ID %s ('%s' en línea %d, origen: %s, destino: %s, servicios: %s) es sombreada por la política superior ID %s ('%s' en línea %d, origen: %s, destino: %s, servicios: %s) en VDOM %s.", 
						pols[j].ID, nameInferior, pols[j].Line, strings.Join(pols[j].SrcAddr, ","), strings.Join(pols[j].DstAddr, ","), strings.Join(pols[j].Service, ","),
						pols[i].ID, nameSuperior, pols[i].Line, strings.Join(pols[i].SrcAddr, ","), strings.Join(pols[i].DstAddr, ","), strings.Join(pols[i].Service, ","),
						vdom)

					results = append(results, CheckResult{
						DeviceName: deviceName, ID: "INT-SHADOW-01", Status: "BAJO", Category: "INTELLIGENCE", Section: "SEC",
						Title: "Regla Sombreada Detectada", VDOM: vdom, Line: pols[j].Line, MitreID: "T1562.001",
						FailedPath: pols[j].ID,
						Value:      pols[i].ID,
						Evidence:   evidenceText,
						BusinessImpact: "Deuda técnica de seguridad y complejidad innecesaria. Las reglas sombreadas nunca se ejecutan y aumentan la probabilidad de errores de configuración humana.",
						TechnicalImpact: "La regla superior es más permisiva y 'oculta' a la regla inferior, haciendo inoperante cualquier control específico de la regla oculta.",
						Remediation: "Eliminar la regla sombreada o reordenarla antes de la regla superior si se pretendía dar prioridad a un tráfico más específico.",
					})
				}
			}
		}
	}

	// 2. Local-In Policy Protection Analysis
	localIn := cfg.Root.ExtractLocalInPolicies()
	hasLocalInRestriction := make(map[string]bool)
	for _, lp := range localIn {
		if lp.Status == "enable" && lp.Action == "accept" {
			if !containsAll(lp.SrcAddr) {
				hasLocalInRestriction[lp.Intf] = true
			}
		}
	}

	// Buscar interfaces con allowaccess y validar exposición WAN
	intfNodes := cfg.Root.FindPath("system.interface")
	for _, intfNode := range intfNodes {
		for _, editNode := range intfNode.Children {
			access := ""
			role := ""
			for _, setNode := range editNode.Children {
				if setNode.Key == "allowaccess" {
					access = setNode.Value
				} else if setNode.Key == "role" {
					role = strings.Trim(strings.ToLower(setNode.Value), "\"")
				}
			}
			if access != "" {
				// Detección Crítica de Gestión en Interfaz WAN (Pública)
				intfLower := strings.ToLower(editNode.Key)
				isWAN := strings.Contains(intfLower, "wan") || role == "wan" || intfLower == "a" // 'a' es ISP_2 en Guadalajara
				hasMgmt := strings.Contains(access, "https") || strings.Contains(access, "ssh") || strings.Contains(access, "http") || strings.Contains(access, "telnet")
				
				if isWAN && hasMgmt {
					results = append(results, CheckResult{
						DeviceName: deviceName, ID: "INT-WAN-MGMT-EXPOSED", Status: "CRÍTICO", Category: "INTELLIGENCE", Section: "NET",
						Title: "Exposición del Plano de Gestión Administrativa en Interfaz WAN (Pública)", VDOM: editNode.VDOM, Line: editNode.Line, MitreID: "T1133",
						Evidence: fmt.Sprintf("La interfaz pública WAN '%s' (rol: %s) tiene permitida la gestión administrativa para los protocolos: %s.", editNode.Key, role, access),
						BusinessImpact: "Exponer la consola de inicio de sesión administrativa (HTTPS, SSH o HTTP) directamente a la WAN pública de internet permite a atacantes de todo el mundo escanear el puerto, realizar ataques de fuerza bruta constantes y explotar vulnerabilidades de día cero del firmware.",
						TechnicalImpact: "Exposición perimetral del plano de control del firewall a ataques externos sin control.",
						Remediation: "Deshabilitar obligatoriamente allowaccess HTTPS, HTTP y SSH en la interfaz WAN pública. Si se requiere administración remota, forzar a los administradores a conectarse primero a través de una VPN cifrada segura antes de acceder a la IP interna de gestión.",
					})
				}

				// Local-In Policy Warning general para interfaces que permiten gestión
				if (strings.Contains(access, "https") || strings.Contains(access, "ssh") || strings.Contains(access, "fgfm")) {
					if !hasLocalInRestriction[editNode.Key] && editNode.Key != "mgmt" && !isWAN {
						results = append(results, CheckResult{
							DeviceName: deviceName, ID: "INT-LOCALIN-01", Status: "MEDIO", Category: "INTELLIGENCE", Section: "NET",
							Title: "Servicios Administrativos sin Local-In Policy", VDOM: editNode.VDOM, Line: editNode.Line, MitreID: "T1190",
							FailedPath: editNode.Key,
							Value:      access,
							Evidence: fmt.Sprintf("La interfaz '%s' tiene allowaccess habilitado (%s), pero no se detectó una Local-In Policy restrictiva para protegerla.", editNode.Key, access),
							BusinessImpact: "Exposición innecesaria del plano de gestión a ataques de red si los Trusted Hosts no están configurados globalmente.",
							TechnicalImpact: "El tráfico administrativo llega al kernel del FortiGate sin filtrado previo por interfaz.",
							Remediation: "Implementar una Local-In Policy para restringir el acceso administrativo a esta interfaz.",
						})
					}
				}
			}
		}
	}

	// 3. Structured Administrative Accounts Audit
	adminNodes := cfg.Root.FindPath("system.admin")
	var superAdmins []string
	var insecureAdmins []string
	
	for _, adminNode := range adminNodes {
		for _, editNode := range adminNode.Children {
			if editNode.Type == parser.NodeEdit {
				adminName := editNode.Key
				accprofile := "default"
				hasMFA := false
				hasTrustHost := false
				
				for _, setNode := range editNode.Children {
					if setNode.Type == parser.NodeSet {
						switch setNode.Key {
						case "accprofile":
							accprofile = strings.Trim(setNode.Value, "\"")
						case "two-factor":
							val := strings.Trim(setNode.Value, "\"")
							if val != "" && val != "disable" {
								hasMFA = true
							}
						case "trusthost1":
							val := strings.Trim(setNode.Value, "\"")
							if val != "" && val != "0.0.0.0 0.0.0.0" {
								hasTrustHost = true
							}
						}
					}
				}
				
				if accprofile == "super_admin" {
					superAdmins = append(superAdmins, adminName)
				}
				
				// Admin crítico expuesto: super_admin o profile alto, sin MFA y sin Trusthost
				if (accprofile == "super_admin" || strings.Contains(strings.ToLower(accprofile), "admin")) && !hasMFA && !hasTrustHost {
					insecureAdmins = append(insecureAdmins, fmt.Sprintf("'%s' (%s)", adminName, accprofile))
				}

				// Detección de Cuenta por Defecto 'admin' activa
				if adminName == "admin" {
					results = append(results, CheckResult{
						DeviceName: deviceName, ID: "INT-ADMIN-DEFAULT-ACTIVE", Status: "ALTO", Category: "INTELLIGENCE", Section: "IAM",
						Title: "Cuenta Administrativa por Defecto 'admin' Activa", VDOM: editNode.VDOM, Line: editNode.Line, MitreID: "T1078.001",
						Evidence: "Se detectó la presencia y actividad de la cuenta con el nombre reservado por defecto 'admin' en el sistema.",
						BusinessImpact: "El uso del nombre de usuario por defecto 'admin' simplifica el trabajo de los atacantes, reduciendo el ataque de fuerza bruta a adivinar únicamente la contraseña. Las buenas prácticas exigen deshabilitar o eliminar este usuario.",
						TechnicalImpact: "Uso de identidades altamente predecibles y de amplio conocimiento público.",
						Remediation: "Crear una cuenta administrativa alternativa con privilegios super_admin y un nombre no predecible, verificar su acceso, y luego deshabilitar o eliminar por completo el usuario por defecto 'admin'.",
					})
				}
			}
		}
	}
	
	// Reportar exceso de super_admins (más de 2 super_admins)
	if len(superAdmins) > 2 {
		results = append(results, CheckResult{
			DeviceName: deviceName, ID: "INT-ADMIN-EXCESS", Status: "MEDIO", Category: "INTELLIGENCE", Section: "IAM",
			Title: "Exceso de Cuentas Administrativas con Privilegios Totales", MitreID: "T1078",
			Evidence: fmt.Sprintf("Se detectaron %d cuentas de tipo 'super_admin' configuradas en el firewall: %s.", len(superAdmins), strings.Join(superAdmins, ", ")),
			BusinessImpact: "El principio de mínimo privilegio dicta que las cuentas con acceso total deben ser limitadas al mínimo necesario. Múltiples cuentas super_admin incrementan la superficie de ataque y dificultan la atribución individual ante incidentes.",
			TechnicalImpact: "Superficie de ataque de gestión ampliada por exceso de identidades privilegiadas.",
			Remediation: "Reducir la cantidad de cuentas super_admin activas (máximo recomendable: 2 para respaldo). Convertir el resto de cuentas a perfiles de acceso restrictivos basados en roles (RBAC).",
		})
	}
	
	// Reportar administradores expuestos sin MFA ni Trusted Hosts
	if len(insecureAdmins) > 0 {
		results = append(results, CheckResult{
			DeviceName: deviceName, ID: "INT-ADMIN-EXPOSED", Status: "CRÍTICO", Category: "INTELLIGENCE", Section: "IAM",
			Title: "Administrador Privilegiado Expuesto sin MFA ni Restricción de Red", MitreID: "T1078.001",
			Evidence: fmt.Sprintf("Las siguientes cuentas de alta jerarquía no tienen MFA habilitado ni Trusted Hosts restrictivos en el plano de red: %s.", strings.Join(insecureAdmins, ", ")),
			BusinessImpact: "Cualquier atacante que obtenga la contraseña de alguna de estas cuentas (por fuerza bruta, filtración o phishing) podrá acceder al firewall desde cualquier parte del mundo y comprometer la red entera sin un segundo factor que lo detenga.",
			TechnicalImpact: "Exposición crítica del plano de gestión debido a la falta de autenticación multifactor y control de origen de red.",
			Remediation: "Habilitar la autenticación de doble factor (set two-factor fortitoken) y configurar obligatoriamente los Trusted Hosts con las IPs o segmentos de red de administración autorizados para cada usuario.",
		})
	}

	// 4. SD-WAN status and SLA Audit
	sdwanNodes := cfg.Root.FindPath("system.sdwan")
	if len(sdwanNodes) > 0 {
		for _, sdwanNode := range sdwanNodes {
			statusEnabled := false
			hasMembers := false
			hasHealthChecks := false
			
			for _, child := range sdwanNode.Children {
				if child.Key == "status" && strings.Trim(child.Value, "\"") == "enable" {
					statusEnabled = true
				}
				if child.Key == "members" || (child.Type == parser.NodeConfig && child.Key == "members") {
					hasMembers = true
				}
				if child.Key == "health-check" || (child.Type == parser.NodeConfig && child.Key == "health-check") {
					hasHealthChecks = true
				}
			}
			
			// Si tiene config de SD-WAN con status enable o tiene múltiples directivas
			if statusEnabled || len(sdwanNode.Children) > 1 {
				for _, subNode := range sdwanNode.Children {
					if subNode.Type == parser.NodeConfig {
						if subNode.Key == "members" && len(subNode.Children) > 0 {
							hasMembers = true
						}
						if subNode.Key == "health-check" && len(subNode.Children) > 0 {
							hasHealthChecks = true
						}
					}
				}

				if !hasMembers || !hasHealthChecks {
					results = append(results, CheckResult{
						DeviceName: deviceName, ID: "INT-SDWAN-SLA-VULN", Status: "MEDIO", Category: "INTELLIGENCE", Section: "NET",
						Title: "SD-WAN Habilitado sin Miembros o SLA de Rendimiento Activos", VDOM: sdwanNode.VDOM, Line: sdwanNode.Line, MitreID: "T1565",
						Evidence: "La característica de SD-WAN está activa en el sistema global, pero carece de interfaces miembro de transporte asociadas o de perfiles Performance SLA (Health Checks) para medir la salud del enlace.",
						BusinessImpact: "El failover dinámico de enlaces no funcionará de manera segura. Si un enlace ISP presenta degradación (alta latencia o pérdida de paquetes), el tráfico no se conmutará automáticamente, provocando interrupciones de negocio.",
						TechnicalImpact: "Ausencia de métricas de calidad de enlace y redundancia de transporte inactiva.",
						Remediation: "Configurar al menos dos interfaces miembro en la zona de SD-WAN (ej. túneles VPN IPsec) y definir perfiles de Performance SLA (conmutación automática por latencia/pérdida de paquetes).",
					})
				}
			}
		}
	}

	// 5. Zero Trust Network Access (ZTNA) Architecture Audit
	ztnaNodes := cfg.Root.FindPath("firewall.access-proxy")
	if len(ztnaNodes) == 0 {
		results = append(results, CheckResult{
			DeviceName: deviceName, ID: "INT-ZTNA-POSTURE-VULN", Status: "BAJO", Category: "INTELLIGENCE", Section: "SEC",
			Title: "ZTNA No Configurado (Arquitectura de VPN Tradicional Legacy)",
			Evidence: "No se detectó configuración de Access Proxy para Zero Trust Network Access (ZTNA) en el dispositivo perimetral.", MitreID: "T1133",
			BusinessImpact: "Operar bajo el modelo clásico de VPN (IPsec/SSL) otorga acceso completo a la red corporativa a cualquier endpoint autenticado. Si el equipo cliente es comprometido, permitirá el movimiento lateral de malware sin restricciones.",
			TechnicalImpact: "Falta de validación continua basada en postura de seguridad del endpoint.",
			Remediation: "Planificar la migración de accesos VPN tradicionales hacia ZTNA utilizando FortiClient, aplicando políticas basadas en la postura de cumplimiento del host.",
		})
	} else {
		for _, proxyNode := range ztnaNodes {
			for _, editNode := range proxyNode.Children {
				if editNode.Type == parser.NodeEdit {
					hasPostureTags := false
					for _, child := range editNode.Children {
						if child.Key == "api-gateway" || (child.Type == parser.NodeConfig && child.Key == "api-gateway") {
							for _, apiEdit := range child.Children {
								for _, apiSet := range apiEdit.Children {
									if apiSet.Key == "posture-tags" && strings.Trim(apiSet.Value, "\"") != "" {
										hasPostureTags = true
									}
								}
							}
						}
					}
					if !hasPostureTags {
						results = append(results, CheckResult{
							DeviceName: deviceName, ID: "INT-ZTNA-TAG-BYPASS", Status: "ALTO", Category: "INTELLIGENCE", Section: "SEC",
							Title: "Regla de ZTNA sin Etiquetas de Postura Restrictivas (Tag Bypass)", VDOM: editNode.VDOM, Line: editNode.Line, MitreID: "T1133",
							Evidence: fmt.Sprintf("El Access Proxy ZTNA '%s' tiene reglas de publicación pero carece de la directiva 'posture-tags' para validar el cumplimiento del cliente.", editNode.Key),
							BusinessImpact: "Cualquier dispositivo ajeno, infectado o desactualizado podrá consumir los recursos internos publicados en el proxy si tiene credenciales válidas, eliminando el beneficio principal de confianza cero.",
							TechnicalImpact: "Acceso no restringido a servicios críticos sin validación de cumplimiento de seguridad del host endpoint.",
							Remediation: "Configurar y asociar etiquetas de postura estrictas (ej. set posture-tags 'Antivirus-Activo' 'Certificado-Corporativo') dentro de las reglas del api-gateway en el access-proxy.",
						})
					}
				}
			}
		}
	}

	// 6. Proactive Threat Hunting & IoC Search
	// A. Auto-Script Infiltrations (MITRE T1059 - Command and Scripting Interpreter)
	scriptNodes := cfg.Root.FindPath("system.auto-script")
	for _, scriptNode := range scriptNodes {
		for _, editNode := range scriptNode.Children {
			if editNode.Type == parser.NodeEdit {
				scriptName := editNode.Key
				scriptVal := ""
				for _, setNode := range editNode.Children {
					if setNode.Key == "script" {
						scriptVal = strings.ToLower(setNode.Value)
						break
					}
				}
				if scriptVal != "" && (strings.Contains(scriptVal, "curl") || strings.Contains(scriptVal, "wget") || strings.Contains(scriptVal, "tftp") || strings.Contains(scriptVal, "ftp ")) {
					results = append(results, CheckResult{
						DeviceName: deviceName, ID: "INT-IOC-AUTO-SCRIPT", Status: "CRÍTICO", Category: "INTELLIGENCE", Section: "IOC",
						Title: "Indicador de Compromiso (IoC): Script Administrativo Sospechoso", VDOM: editNode.VDOM, Line: editNode.Line, MitreID: "T1059",
						Evidence: fmt.Sprintf("El script automático '%s' contiene comandos de descarga externa no autorizados: '%s'.", scriptName, scriptVal),
						BusinessImpact: "La presencia de comandos de descarga en scripts de persistencia del firewall indica con alta probabilidad un compromiso previo o la preparación para una exfiltración masiva de datos o despliegue de malware de segunda etapa.",
						TechnicalImpact: "Persistencia activa de nivel de sistema con capacidades de descarga remota.",
						Remediation: "Eliminar el script inmediatamente de la configuración con 'delete' y abrir una investigación forense (DFIR) completa del equipo.",
					})
				}
			}
		}
	}

	// 7. Crypto-Audit de Higiene y Robustez de Hashes (INT-CRYPTO-*)
	traverseSecrets(cfg.Root, 0, func(node *parser.ASTNode) {
		val := strings.Trim(node.Value, "\"")
		path := node.GetPath()
		
		// Detección de cifrado reversible/obsoleto "ENC"
		if strings.HasPrefix(val, "ENC ") {
			// Determinar si es cuenta administrativa o VPN/secreto
			isVPN := strings.Contains(strings.ToLower(path), "vpn") || strings.Contains(strings.ToLower(path), "psk")
			
			if isVPN {
				results = append(results, CheckResult{
					DeviceName: deviceName, ID: "INT-CRYPTO-REV-PSK", Status: "CRÍTICO", Category: "HARDENING", Section: "NET",
					Title: "Clave Precompartida VPN (PSK) Almacenada con Cifrado Reversible (ENC)", VDOM: node.VDOM, Line: node.Line, MitreID: "T1552.004",
					FailedPath: path, Value: val,
					Evidence: fmt.Sprintf("La clave VPN precompartida '%s' en la línea %d está almacenada bajo el esquema de cifrado débil reversible 'ENC'.", path, node.Line),
					BusinessImpact: "El algoritmo 'ENC' de FortiGate utiliza una clave estática XOR globalmente conocida. Cualquier persona o malware con acceso de lectura a la configuración podrá revertir el hash a texto plano en milisegundos, comprometiendo la clave IPSec y permitiendo la interceptación o suplantación de tráfico VPN.",
					TechnicalImpact: "Cifrado trivialmente reversible de secretos y claves precompartidas.",
					Remediation: "Utilizar un esquema de cifrado de secretos local más robusto mediante una contraseña maestra del sistema (set private-key-encryption enable), o migrar a autenticación robusta mediante certificados digitales (X.509).",
					ISO27001: "A.10.1.1", NIST: "SC-13", PCI: "PCI-Requirement-3.5",
				})
			} else {
				results = append(results, CheckResult{
					DeviceName: deviceName, ID: "INT-CRYPTO-REV-PWD", Status: "CRÍTICO", Category: "HARDENING", Section: "IAM",
					Title: "Contraseña Administrativa Almacenada con Cifrado Reversible (ENC)", VDOM: node.VDOM, Line: node.Line, MitreID: "T1552.004",
					FailedPath: path, Value: val,
					Evidence: fmt.Sprintf("La contraseña de acceso administrativo '%s' en la línea %d está almacenada bajo el esquema de cifrado débil reversible 'ENC'.", path, node.Line),
					BusinessImpact: "Las contraseñas cifradas con el esquema heredado 'ENC' se pueden descifrar instantáneamente usando herramientas públicas. Si un atacante roba el archivo de configuración, obtendrá la contraseña en texto plano del administrador y comprometerá por completo el firewall y la red corporativa.",
					TechnicalImpact: "Fuga inmediata de credenciales administrativas en texto plano en caso de exposición del backup.",
					Remediation: "Forzar la actualización del firmware o la re-generación del hash administrativo usando un algoritmo robusto con sal (SHA256 de tipo 'SH2' o bcrypt). Se recomienda habilitar una contraseña maestra de cifrado local en el FortiGate.",
					ISO27001: "A.9.4.3", NIST: "IA-5", PCI: "PCI-Requirement-8.2",
				})
			}
		}
	})

	return results
}

func AnalyzeObjectIntelligence(deviceName string, cfg *parser.FGTConfig) []CheckResult {
	var results []CheckResult
	objects := cfg.Root.ExtractObjects()
	
	// 1. Duplicate Address Objects (Same Value)
	valMap := make(map[string][]string) // Value -> []Names
	nameToLine := make(map[string]int)
	nameToVDOM := make(map[string]string)
	for _, obj := range objects {
		if obj.Type == "address" && obj.Value != "" && obj.Value != "0.0.0.0 0.0.0.0" {
			valMap[obj.Value] = append(valMap[obj.Value], obj.Name)
			nameToLine[obj.Name] = obj.Line
			nameToVDOM[obj.Name] = obj.VDOM
		}
	}

	for val, names := range valMap {
		if len(names) > 1 {
			results = append(results, CheckResult{
				DeviceName: deviceName, ID: "INT-OBJ-DUP-01", Status: "BAJO", Category: "INTELLIGENCE", Section: "HIGIENE",
				Title: "Objetos de Dirección Duplicados", VDOM: nameToVDOM[names[0]], Line: nameToLine[names[0]],
				Evidence: fmt.Sprintf("Los objetos %s comparten el mismo valor: %s.", strings.Join(names, ", "), val),
				BusinessImpact: "Tener múltiples nombres asignados a la misma dirección IP o segmento de red (ej. definir 'LAN_Vlan10', 'Vlan10_users' y 'RED_INTERNA' para la misma IP) incrementa exponencialmente el error humano en la administración diaria del firewall. Un administrador podría modificar un objeto pensando que está asegurando un segmento, mientras que las reglas activas usan el objeto duplicado, dejando brechas de seguridad abiertas.",
				TechnicalImpact: "Redundancia y falta de unicidad en la base de datos de objetos, impidiendo la consistencia de políticas.",
				Remediation: "Consolidar los objetos duplicados bajo una única nomenclatura estándar de la empresa. Reemplazar su uso en todas las políticas activas y eliminar los duplicados obsoletos.",
			})
		}
	}

	// 2. Custom Services Overlap (Simplified)
	svcs := cfg.Root.ExtractServiceCustoms()
	portMap := make(map[string][]string) // Port -> []Names
	for _, s := range svcs {
		if s.Port != "" {
			portMap[s.Protocol+":"+s.Port] = append(portMap[s.Protocol+":"+s.Port], s.Name)
		}
	}

	for port, names := range portMap {
		if len(names) > 1 {
			results = append(results, CheckResult{
				DeviceName: deviceName, ID: "INT-SVC-DUP-01", Status: "BAJO", Category: "INTELLIGENCE", Section: "HIGIENE",
				Title: "Definiciones de Servicios de Red Duplicados (Redundancia de Puertos)",
				Evidence: fmt.Sprintf("Los servicios %s definen el mismo rango de puertos: %s.", strings.Join(names, ", "), port),
				BusinessImpact: "Tener múltiples objetos para el mismo puerto de red (ej. definir tres objetos diferentes para el puerto TCP 21 de FTP) genera confusión operativa extrema, dificulta la auditoría de políticas y aumenta el riesgo de aplicar reglas equivocadas que expongan servicios críticos de manera involuntaria.",
				TechnicalImpact: "Deuda técnica en la base de datos de objetos del firewall. Dificulta el mantenimiento y la lectura de las políticas.",
				Remediation: "Eliminar las definiciones de servicios duplicadas. Utilizar un único objeto estándar para cada puerto/protocolo y actualizar las políticas de seguridad para que apunten a ese único objeto consolidado.",
			})
		}
	}

	return results
}

func isShadowed(superior, inferior parser.FirewallPolicy) bool {
	if superior.Status == "disable" { return false }
	if superior.Action != inferior.Action { return false }
	
	// Si la superior es ANY ANY ANY, sombrea a cualquier inferior con la misma acción
	if containsAll(superior.SrcAddr) && containsAll(superior.DstAddr) && containsAll(superior.Service) {
		return true
	}
	
	// Caso particular: misma IP de origen/destino pero superior es más permisiva en servicios
	if sameList(superior.SrcAddr, inferior.SrcAddr) && sameList(superior.DstAddr, inferior.DstAddr) {
		if containsAll(superior.Service) { return true }
	}

	return false
}

func sameList(a, b []string) bool {
	if len(a) != len(b) { return false }
	for i := range a {
		if a[i] != b[i] { return false }
	}
	return true
}

func containsAll(list []string) bool {
	for _, s := range list {
		low := strings.ToLower(s)
		if low == "all" || low == "any" { return true }
	}
	return false
}

func traverseSecrets(n *parser.ASTNode, depth int, fn func(*parser.ASTNode)) {
	if n == nil {
		return
	}
	if depth > 50 {
		return
	}
	if n.Type == parser.NodeSet {
		keyLower := strings.ToLower(n.Key)
		if keyLower == "password" || keyLower == "psksecret" || keyLower == "passwd" || keyLower == "private-key" || keyLower == "secret" || keyLower == "passphrase" {
			fn(n)
		}
	}
	for _, child := range n.Children {
		traverseSecrets(child, depth+1, fn)
	}
}

func DiscoverTopology(deviceName string, cfg *parser.FGTConfig) []CheckResult {
	var results []CheckResult
	services := []struct{ Path, Name string }{
		{"vpn.ssl.settings", "VPN SSL"}, {"vpn.ipsec.phase1-interface", "VPN IPSec"}, {"system.central-management", "FortiManager"},
	}
	for _, s := range services {
		if len(cfg.Root.FindPath(s.Path)) > 0 {
			results = append(results, CheckResult{
				DeviceName: deviceName, Category: "TOPOLOGY", Title: "TOPOLOGÍA Y SERVICIOS EXPUESTOS", Passed: true,
				Evidence: fmt.Sprintf("Servicio de %s detectado como activo en la configuración.", s.Name),
			})
		}
	}
	return results
}

func checkTrigger(operator, current, target string) bool {
	if target == "*" { return true }
	switch operator {
	case "exact": return current == target
	case "contains": return strings.Contains(current, target)
	case "token_match":
		tokens := strings.Fields(current)
		for _, t := range tokens {
			if t == target { return true }
		}
		return false
	case "not_contains": return !strings.Contains(current, target)
	default: return current == target
	}
}
