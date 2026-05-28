package report

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"
	"tricera/internal/engine"
	"tricera/internal/intelligence"
	"tricera/internal/matcher"
	"tricera/internal/parser"
)

type HTMLReport struct {
	Generated       string
	Date            string
	GlobalScore     int
	TotalCVEs       int
	TotalHardening  int
	TotalPassed     int
	TotalControls   int
	Metadata        AuditMetadata
	ExecActions     []ExecAction
	FindingGroups   []FindingGroup
	CisaKevFindings []intelligence.ThreatEnrichment
	EnrichedPSIRT   []intelligence.ThreatEnrichment
	PSIRT           PSIRTSummary
	CISSummary      []CISModuleSummary
	TechnicalCIS    []FindingsSection
	Compliance      ComplianceSummary
	EliteStats      AuditCoverageSummary
	AdminUsers      []AdminUserDetail
	Policies        []parser.FirewallPolicy
	Devices         []DeviceDetail
	AuditDuration   string
}

type DeviceDetail struct {
	Hostname        string
	Version         string
	TopologyMermaid string
	AdminUsers      []AdminUserDetail
	Policies        []parser.FirewallPolicy
}

type AdminUserDetail struct {
	Name         string
	Profile      string
	VDOM         string
	HasMFA       bool
	HasTrustHost bool
	TrustHosts   string
	Line         int
}

type AuditMetadata struct {
	Hostname string
	Version  string
	Date     string
}

type ExecAction struct {
	Title      string
	Reason     string
	Evidence   string
	Action     string
	Workaround string
	Priority   string 
}

type CISModuleSummary struct {
	Name    string
	Count   int
	Details string
	Icon    string
}

type FindingsSection struct {
	ID       string
	Name     string
	Icon     string
	Findings []engine.CheckResult
}

type ComplianceSummary struct {
	ISO27001 float64
	NIST     float64
	PCI      float64
	FailedISO  []engine.CheckResult
	FailedNIST []engine.CheckResult
	FailedPCI  []engine.CheckResult
}

func ExtractAdminsForConfig(cfg *parser.FGTConfig) []AdminUserDetail {
	var admins []AdminUserDetail
	if cfg == nil {
		return admins
	}
	adminNodes := cfg.Root.FindPath("system.admin")
	for _, adminNode := range adminNodes {
		for _, editNode := range adminNode.Children {
			if editNode.Type == parser.NodeEdit {
				adm := AdminUserDetail{
					Name:    editNode.Key,
					Profile: "super_admin", // Default
					VDOM:    "root",
					Line:    editNode.Line,
				}
				for _, setNode := range editNode.Children {
					if setNode.Key == "accprofile" {
						adm.Profile = strings.Trim(setNode.Value, "\"")
					}
					if setNode.Key == "vdom" {
						adm.VDOM = strings.Trim(setNode.Value, "\"")
					}
					if setNode.Key == "two-factor" {
						adm.HasMFA = true
					}
					if strings.HasPrefix(setNode.Key, "trusthost") {
						adm.HasTrustHost = true
						rawIP := strings.Trim(setNode.Value, "\"")
						if adm.TrustHosts == "" {
							adm.TrustHosts = rawIP
						} else {
							adm.TrustHosts += ", " + rawIP
						}
					}
				}
				admins = append(admins, adm)
			}
		}
	}
	return admins
}

func ExportHTML(results []engine.CheckResult, psirtFindings []matcher.PSIRTFinding, version string, cfg *parser.FGTConfig, path string, devices []DeviceDetail, duration time.Duration) error {
	r := HTMLReport{
		Generated:     time.Now().Format("2006-01-02 15:04:05"),
		Date:          time.Now().Format("02 Jan 2006"),
		TotalControls: len(results),
		PSIRT:         GeneratePSIRTSummary(psirtFindings),
		AuditDuration: fmt.Sprintf("%.2fs", duration.Seconds()),
	}
	r.Metadata.Version = version
	r.Metadata.Date = r.Date
	if len(results) > 0 {
		r.Metadata.Hostname = results[0].DeviceName
	}
	
	asset := intelligence.AssetFingerprint{Hostname: r.Metadata.Hostname, Version: version}
	for _, f := range psirtFindings {
		if f.Advisory.ID == "ERROR_FETCH" {
			continue
		}
		enriched := intelligence.EnrichAdvisory(f.Advisory, asset)
		if f.State == intelligence.ExposureConfirmed {
			enriched.EvidenceSummary = "Exposición activa confirmada: El servicio/componente afectado está habilitado en tu configuración."
			enriched.ExploitStatus = "Activo / Expuesto"
		} else if f.State == intelligence.NotApplicableByConfig {
			enriched.EvidenceSummary = "Vulnerabilidad NO activa: El componente afectado está deshabilitado en tu configuración."
			enriched.ExploitStatus = "Mitigado por Configuración"
		} else if f.State == intelligence.ManualReviewRequired {
			enriched.EvidenceSummary = "Exposición potencial: Requiere revisión manual operativa (servicios de sistema, GUI/CLI o kernel)."
			enriched.ExploitStatus = "Revisión Manual"
		} else {
			enriched.EvidenceSummary = "Vulnerabilidad potencial por versión de firmware. FortiOS " + version + " aparece afectada."
			enriched.ExploitStatus = "Potencial por Versión"
		}
		r.EnrichedPSIRT = append(r.EnrichedPSIRT, enriched)
		if enriched.IsCisaKEV { r.CisaKevFindings = append(r.CisaKevFindings, enriched) }
	}

	// Extraer políticas de firewall auditadas
	if cfg != nil {
		r.Policies = cfg.Root.ExtractPolicies()
	}

	// Extraer administradores detallados
	admins := ExtractAdminsForConfig(cfg)
	r.AdminUsers = admins

	r.EliteStats = BuildAuditCoverageSummary(cfg, results, r.EnrichedPSIRT)

	if len(devices) == 0 && cfg != nil {
		dev := DeviceDetail{
			Hostname:        r.Metadata.Hostname,
			Version:         version,
			TopologyMermaid: r.EliteStats.TopologyMermaid,
			AdminUsers:      r.AdminUsers,
			Policies:        r.Policies,
		}
		r.Devices = []DeviceDetail{dev}
	} else if len(devices) > 0 {
		r.Devices = devices
	}
	r.FindingGroups = AggregateFindings(results, cfg)
	r.ExecActions = buildExecActions(r.EnrichedPSIRT)
	r.CISSummary, r.TechnicalCIS = buildCISSections(results)
	r.Compliance = calculateCompliance(results)

	r.GlobalScore = r.PSIRT.GlobalRiskScore
	r.TotalPassed = 0
	for _, res := range results {
		if res.Passed { r.TotalPassed++ }
	}
	if r.TotalControls > 0 {
		r.TotalHardening = (r.TotalPassed * 100) / r.TotalControls
	}

	funcMap := template.FuncMap{
		"sub": func(a, b int) int { return a - b },
		"percent": func(f float64) string { return fmt.Sprintf("%.1f%%", f*100) },
		"toLower": strings.ToLower,
		"perc": func(a, b int) string {
			if b == 0 { return "0%" }
			return fmt.Sprintf("%.1f%%", float64(a)*100/float64(b))
		},
	}

	tmpl := template.Must(template.New("report").Funcs(funcMap).Parse(htmlTemplate))
	// SEC-FIX VULN-007: Crear archivo con permisos restrictivos (solo lectura/escritura para el propietario)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil { return err }
	defer f.Close()

	return tmpl.Execute(f, r)
}

func consolidateResults(results []engine.CheckResult) []engine.CheckResult {
	type consolidated struct {
		base     engine.CheckResult
		evidences []string
		lines     []int
		elements  []string
	}
	
	groups := make(map[string]*consolidated)
	var orderedIds []string
	
	for _, res := range results {
		if res.Passed { continue }
		
		group, ok := groups[res.ID]
		if !ok {
			group = &consolidated{base: res}
			groups[res.ID] = group
			orderedIds = append(orderedIds, res.ID)
		}
		
		element := ""
		if strings.Contains(res.FailedPath, "system.interface.") {
			parts := strings.Split(res.FailedPath, ".")
			if len(parts) >= 3 {
				element = parts[2]
			}
		}
		
		if element != "" {
			group.elements = append(group.elements, fmt.Sprintf("%s (línea %d)", element, res.Line))
		} else if res.FailedPath != "" {
			group.elements = append(group.elements, fmt.Sprintf("línea %d (%s)", res.Line, res.FailedPath))
		} else {
			group.evidences = append(group.evidences, res.Evidence)
		}
		group.lines = append(group.lines, res.Line)
	}
	
	var consolidatedList []engine.CheckResult
	for _, id := range orderedIds {
		g := groups[id]
		res := g.base
		
		if len(g.elements) > 0 {
			res.Evidence = fmt.Sprintf("Fallas detectadas en: %s.", strings.Join(g.elements, ", "))
		} else if len(g.evidences) > 1 {
			res.Evidence = fmt.Sprintf("Riesgo detectado en múltiples configuraciones (%d fallas detectadas).", len(g.evidences))
		}
		
		consolidatedList = append(consolidatedList, res)
	}
	return consolidatedList
}

func calculateCompliance(results []engine.CheckResult) ComplianceSummary {
	var isoPass, isoTotal, nistPass, nistTotal, pciPass, pciTotal int
	summary := ComplianceSummary{}
	
	var rawISO, rawNIST, rawPCI []engine.CheckResult
	
	for _, res := range results {
		if res.ISO27001 != "" {
			isoTotal++
			if res.Passed { 
				isoPass++ 
			} else {
				rawISO = append(rawISO, res)
			}
		}
		if res.NIST != "" {
			nistTotal++
			if res.Passed { 
				nistPass++ 
			} else {
				rawNIST = append(rawNIST, res)
			}
		}
		if res.PCI != "" {
			pciTotal++
			if res.Passed { 
				pciPass++ 
			} else {
				rawPCI = append(rawPCI, res)
			}
		}
	}
	
	summary.FailedISO = consolidateResults(rawISO)
	summary.FailedNIST = consolidateResults(rawNIST)
	summary.FailedPCI = consolidateResults(rawPCI)
	
	if isoTotal > 0 { summary.ISO27001 = float64(isoPass) / float64(isoTotal) }
	if nistTotal > 0 { summary.NIST = float64(nistPass) / float64(nistTotal) }
	if pciTotal > 0 { summary.PCI = float64(pciPass) / float64(pciTotal) }
	return summary
}

func buildExecActions(enriched []intelligence.ThreatEnrichment) []ExecAction {
	var actions []ExecAction
	for _, e := range enriched {
		if (e.TriceraPriority == "P1 CRÍTICO" || e.IsCisaKEV) && len(actions) < 5 {
			actions = append(actions, ExecAction{
				Title:      "CRÍTICO: " + e.PSIRTID,
				Reason:     fmt.Sprintf("%s. EPSS: %s.", e.ExploitStatus, fmt.Sprintf("%.1f%%", e.EPSSScore*100)),
				Evidence:   e.EvidenceSummary,
				Action:     e.ImmediateAction,
				Workaround: e.VendorWorkaround,
				Priority:   e.TriceraPriority,
			})
		}
	}
	return actions
}

func buildCISSections(results []engine.CheckResult) ([]CISModuleSummary, []FindingsSection) {
	modules := map[string]*CISModuleSummary{
		"NET": {Name: "Red e Interfaces", Icon: "🌐"},
		"IAM": {Name: "Identidad y Acceso", Icon: "👤"},
		"SEC": {Name: "Políticas de Firewall", Icon: "🛡️"},
		"MGMT": {Name: "Trazabilidad de Logs", Icon: "🛠️"},
		"SISTEMA": {Name: "Línea Base y Hardening", Icon: "⚙️"},
	}
	sections := map[string]*FindingsSection{
		"NET": {ID: "NET", Name: "Seguridad de Red e Interfaces Expuestas", Icon: "🌐"},
		"IAM": {ID: "IAM", Name: "Control de Acceso y Gestión de Identidad (IAM)", Icon: "👤"},
		"SEC": {ID: "SEC", Name: "Auditoría de Políticas e Higiene de Reglas", Icon: "🛡️"},
		"MGMT": {ID: "MGMT", Name: "Auditoría de Logs y Trazabilidad Forense", Icon: "🛠️"},
		"SISTEMA": {ID: "SISTEMA", Name: "Endurecimiento de Plataforma (Host Hardening)", Icon: "⚙️"},
	}

	var tech []FindingsSection
	var summary []CISModuleSummary

	for _, r := range results {
		if r.Category == "TOPOLOGY" || r.Passed || r.Category == "INFO" || r.Category == "INTELLIGENCE" { continue }
		sec := r.Section
		if sec == "" || sec == "MISC" { sec = "SISTEMA" }

		if s, ok := sections[sec]; ok {
			s.Findings = append(s.Findings, r)
		}
		if m, ok := modules[sec]; ok {
			m.Count++
		}
	}

	keys := []string{"NET", "IAM", "SEC", "MGMT", "SISTEMA"}
	for _, k := range keys {
		if sections[k] != nil && len(sections[k].Findings) > 0 {
			tech = append(tech, *sections[k])
			m := modules[k]
			summary = append(summary, *m)
		}
	}
	return summary, tech
}

const htmlTemplate = `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Executive Risk Brief v5.3 — Tricera Audit Full Capability</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <script>
        mermaid.initialize({
            startOnLoad: true,
            theme: 'dark',
            themeVariables: {
                background: '#0b0f19',
                primaryColor: '#1e293b',
                primaryTextColor: '#f8fafc',
                lineColor: '#38bdf8',
                secondaryColor: '#151b28',
                tertiaryColor: '#0b0f19'
            },
            flowchart: {
                useMaxWidth: true,
                htmlLabels: true,
                curve: 'basis'
            }
        });

        function switchDevice(hostname) {
            var sections = document.querySelectorAll('.device-section');
            sections.forEach(function(sec) {
                sec.style.display = 'none';
            });
            var selected = document.querySelectorAll('.device-section-' + hostname);
            selected.forEach(function(sec) {
                if (sec.innerHTML.includes('class="mermaid"')) {
                    sec.style.display = 'flex';
                } else {
                    sec.style.display = 'block';
                }
            });
        }

        // StegoSec ATT&CK Map highlighting engine
        function highlightMitre(tacticId) {
            document.querySelectorAll('.mitre-column').forEach(c => c.style.borderColor = 'var(--border)');
            document.querySelectorAll('.mitre-column').forEach(c => c.style.background = 'var(--surface)');
            if (tacticId) {
                const target = document.getElementById('mitre-' + tacticId);
                if (target) {
                    target.style.borderColor = 'var(--primary)';
                    target.style.background = 'rgba(56, 189, 248, 0.08)';
                }
            }
        }
    </script>
    <style>
        :root {
            --bg: #0b0f19;
            --surface: #151b28;
            --surface-hover: #1e2638;
            --primary: #38bdf8;
            --secondary: #94a3b8;
            --accent: #8b5cf6;
            --danger: #ef4444;
            --warn: #f59e0b;
            --success: #10b981;
            --info: #3b82f6;
            --border: rgba(255, 255, 255, 0.08);
            --text: #f8fafc;
            --text-dim: #94a3b8;
            --glass: rgba(255, 255, 255, 0.03);
            --glass-border: rgba(255, 255, 255, 0.1);
            --cyber-neon: #ff2a5f;
        }

        /* Neon threat gauge animation */
        @keyframes pulse-neon {
            0% { filter: drop-shadow(0 0 2px var(--cyber-neon)); }
            50% { filter: drop-shadow(0 0 12px var(--cyber-neon)); }
            100% { filter: drop-shadow(0 0 2px var(--cyber-neon)); }
        }
        .neon-glow {
            animation: pulse-neon 3s infinite ease-in-out;
        }

        /* MITRE ATT&CK Matrix styling */
        .mitre-grid {
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 15px;
            margin-bottom: 40px;
        }
        .mitre-column {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 15px;
            transition: all 0.3s ease;
            display: flex;
            flex-direction: column;
            gap: 10px;
        }
        .mitre-column:hover {
            transform: translateY(-2px);
            border-color: var(--primary);
            box-shadow: 0 4px 20px rgba(56, 189, 248, 0.15);
        }
        .mitre-header {
            font-size: 11px;
            font-weight: 800;
            text-transform: uppercase;
            color: var(--primary);
            letter-spacing: 0.5px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
            padding-bottom: 8px;
            margin-bottom: 5px;
        }
        .mitre-card {
            background: rgba(0, 0, 0, 0.25);
            border-radius: 8px;
            padding: 10px;
            font-size: 11.5px;
            border-left: 3px solid var(--secondary);
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .mitre-card:hover {
            background: rgba(255, 255, 255, 0.03);
            border-left-color: var(--primary);
        }
        .mitre-card.crit {
            border-left-color: var(--danger);
            background: rgba(239, 68, 68, 0.05);
        }
        .mitre-card.warn {
            border-left-color: var(--warn);
            background: rgba(245, 158, 11, 0.05);
        }
        .mitre-card.pass {
            border-left-color: var(--success);
            opacity: 0.7;
        }
        .mitre-tech-id {
            font-family: 'JetBrains Mono', monospace;
            font-size: 9px;
            opacity: 0.5;
            display: block;
            margin-top: 4px;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            background-color: var(--bg); 
            color: var(--text); 
            font-family: 'Outfit', sans-serif; 
            line-height: 1.6; 
            background-image: radial-gradient(circle at 50% -20%, #1e293b 0%, transparent 50%);
            scroll-behavior: smooth;
        }

        .container { max-width: 1240px; margin: 0 auto; padding: 40px 20px; }
        
        /* PORTADA */
        .cover { height: 60vh; display: flex; flex-direction: column; justify-content: center; border-bottom: 1px solid var(--border); margin-bottom: 80px; position: relative; overflow: hidden; }
        .cover::after { content: "TRICERA"; position: absolute; right: -50px; bottom: -50px; font-size: 200px; font-weight: 800; opacity: 0.02; letter-spacing: -10px; }
        .brand { color: var(--primary); font-weight: 800; font-size: 14px; letter-spacing: 5px; text-transform: uppercase; margin-bottom: 15px; }
        .title { font-size: 64px; font-weight: 800; line-height: 1; margin-bottom: 30px; letter-spacing: -3px; }
        
        .metadata-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 40px; }
        .metadata-item { border-left: 2px solid var(--primary); padding-left: 20px; }
        .metadata-label { font-size: 10px; text-transform: uppercase; color: var(--text-dim); margin-bottom: 5px; font-weight: 600; letter-spacing: 1px; }
        .metadata-val { font-size: 18px; font-weight: 600; }

        /* SECTIONS */
        .section-title { font-size: 28px; font-weight: 800; margin: 100px 0 40px 0; display: flex; align-items: center; gap: 20px; letter-spacing: -1px; }
        .section-title::before { content: ""; width: 40px; height: 4px; background: var(--primary); border-radius: 2px; }

        .coverage-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; margin-bottom: 30px; }
        .coverage-card { background: var(--surface); border: 1px solid var(--border); border-radius: 24px; padding: 30px; }
        .coverage-title { font-size: 16px; font-weight: 800; margin-bottom: 20px; color: var(--primary); text-transform: uppercase; letter-spacing: 1px; }
        
        .stats-table { width: 100%; border-collapse: collapse; }
        .stats-table td { padding: 10px 0; border-bottom: 1px solid rgba(255,255,255,0.03); font-size: 14px; }
        .stats-table td:last-child { text-align: right; font-weight: 600; }
        .stats-table td:first-child { color: var(--text-dim); }

        .tag { font-size: 10px; font-weight: 800; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; }
        .tag-active { background: rgba(16, 185, 129, 0.1); color: var(--success); border: 1px solid var(--success); }
        .tag-inactive { background: rgba(255, 255, 255, 0.05); color: var(--text-dim); border: 1px solid var(--text-dim); }

        .link-detail { font-size: 10px; color: var(--primary); text-decoration: none; text-transform: uppercase; font-weight: 800; display: inline-flex; align-items: center; gap: 5px; }
        .link-detail:hover { text-decoration: underline; }

        /* SNAPSHOT */
        .snapshot-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 60px; }
        .snapshot-card { background: var(--glass); border: 1px solid var(--glass-border); padding: 30px; border-radius: 28px; }
        .snap-label { font-size: 11px; font-weight: 800; text-transform: uppercase; color: var(--secondary); margin-bottom: 15px; }
        .snap-val { font-size: 24px; font-weight: 800; margin-bottom: 10px; display: flex; align-items: center; gap: 10px; }
        .snap-desc { font-size: 13px; color: var(--text-dim); line-height: 1.4; }

        /* PRIORITIES */
        .priority-item { background: var(--surface); border: 1px solid var(--border); border-radius: 24px; padding: 35px; margin-bottom: 20px; display: grid; grid-template-columns: 100px 1fr 250px; gap: 30px; align-items: center; border-left: 8px solid var(--danger); }
        .priority-p { font-size: 32px; font-weight: 800; color: var(--danger); text-align: center; }
        .priority-content h4 { font-size: 18px; margin-bottom: 8px; }
        .priority-action { background: rgba(56, 189, 248, 0.05); border: 1px dashed var(--primary); padding: 20px; border-radius: 12px; font-size: 12px; }

        /* TABLES */
        .card { background: var(--surface); border: 1px solid var(--border); border-radius: 24px; padding: 35px; margin-bottom: 40px; }
        .badge { font-size: 10px; font-weight: 800; padding: 4px 10px; border-radius: 6px; text-transform: uppercase; }
        .badge-danger { background: rgba(239, 68, 68, 0.15); color: var(--danger); border: 1px solid var(--danger); }
        .badge-warn { background: rgba(245, 158, 11, 0.15); color: var(--warn); border: 1px solid var(--warn); }
        .badge-info { background: rgba(56, 189, 248, 0.15); color: var(--primary); border: 1px solid var(--primary); }
        .badge-success { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid var(--success); }
        
        .badge-danger-glow {
            background: rgba(239, 68, 68, 0.15);
            color: #f87171;
            border: 1px solid rgba(239, 68, 68, 0.4);
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.15);
            padding: 4px 10px;
            border-radius: 20px;
            font-weight: 700;
            display: inline-block;
        }
        .badge-success-glow {
            background: rgba(34, 197, 94, 0.15);
            color: #4ade80;
            border: 1px solid rgba(34, 197, 94, 0.4);
            box-shadow: 0 0 10px rgba(34, 197, 94, 0.15);
            padding: 4px 10px;
            border-radius: 20px;
            font-weight: 700;
            display: inline-block;
        }
        .badge-warn-glow {
            background: rgba(245, 158, 11, 0.15);
            color: #fbbf24;
            border: 1px solid rgba(245, 158, 11, 0.4);
            box-shadow: 0 0 10px rgba(245, 158, 11, 0.15);
            padding: 4px 10px;
            border-radius: 20px;
            font-weight: 700;
            display: inline-block;
        }
        .badge-info-glow {
            background: rgba(59, 130, 246, 0.15);
            color: #60a5fa;
            border: 1px solid rgba(59, 130, 246, 0.4);
            box-shadow: 0 0 10px rgba(59, 130, 246, 0.15);
            padding: 4px 10px;
            border-radius: 20px;
            font-weight: 700;
            display: inline-block;
        }
        
        .grc-pill-container {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 30px;
        }
        .grc-pill {
            background: rgba(30, 41, 59, 0.3);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 20px;
            text-align: center;
            transition: all 0.3s ease;
        }
        .grc-pill:hover {
            transform: translateY(-2px);
            border-color: rgba(255,255,255,0.15);
            background: rgba(30, 41, 59, 0.5);
        }
        .grc-pill-num {
            font-size: 28px;
            font-weight: 800;
            margin-bottom: 5px;
            font-family: 'Outfit', sans-serif;
        }
        .grc-pill-label {
            font-size: 11px;
            text-transform: uppercase;
            color: var(--text-dim);
            font-weight: 600;
            letter-spacing: 0.5px;
        }

        .data-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .data-table th { text-align: left; padding: 15px; background: rgba(255,255,255,0.02); color: var(--text-dim); text-transform: uppercase; font-size: 10px; letter-spacing: 1px; }
        .data-table td { padding: 15px; border-bottom: 1px solid var(--border); vertical-align: top; }
        .data-table tr:hover { background: rgba(255,255,255,0.01); }

        .cli-box { background: #0f172a; border-radius: 10px; padding: 15px; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #f8fafc; margin-top: 10px; border: 1px solid var(--border); position: relative; }
        .cli-label { position: absolute; right: 10px; top: -10px; background: var(--primary); color: var(--bg); font-size: 8px; font-weight: 800; padding: 2px 6px; border-radius: 4px; }

        .evidence-text { color: var(--primary); font-family: 'JetBrains Mono', monospace; font-size: 11px; }
        
        .mermaid {
            width: 100% !important;
            display: flex;
            justify-content: center;
        }
        .mermaid svg {
            width: 100% !important;
            max-width: 1200px !important;
            height: auto !important;
            min-height: 550px !important;
        }

        /* RISK CARDS */
        .risk-card { background: rgba(30, 41, 59, 0.4); border: 1px solid var(--border); border-radius: 16px; padding: 25px; margin-bottom: 20px; }
        .risk-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 15px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 15px;}
        .risk-title { font-size: 18px; font-weight: 800; color: var(--text); display:flex; align-items:center; gap: 10px;}
        .risk-id { font-family: 'JetBrains Mono', monospace; font-size: 11px; background: rgba(255,255,255,0.1); padding: 3px 8px; border-radius: 4px; color: var(--secondary);}
        .impact-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        .impact-box { background: rgba(0,0,0,0.2); padding: 15px; border-radius: 12px; border-left: 3px solid; }
        .impact-box.biz { border-color: var(--warn); }
        .impact-box.tech { border-color: var(--primary); }
        .impact-title { font-size: 11px; text-transform: uppercase; font-weight: 800; margin-bottom: 5px; opacity:0.8;}
        .impact-text { font-size: 13px; line-height: 1.5; color: var(--text-dim); }
        .risk-evidence { background: #0f172a; padding: 15px; border-radius: 10px; font-family: 'JetBrains Mono', monospace; font-size: 11px; color: var(--primary); border: 1px solid rgba(56, 189, 248, 0.2); margin-bottom: 15px;}
        .risk-action { display: flex; align-items:center; gap: 10px; background: rgba(16, 185, 129, 0.05); padding: 15px; border-radius: 12px; border: 1px dashed rgba(16, 185, 129, 0.3);}
        
        .ciso-tooltip { background: rgba(56, 189, 248, 0.05); border-left: 4px solid var(--primary); padding: 15px 20px; margin-bottom: 25px; border-radius: 0 8px 8px 0; font-size: 14px; opacity: 0.9; }
    </style>
</head>
<body>
    <div class="container">
        <!-- PORTADA -->
        <div class="cover">
            <div class="brand"><span style="font-size: 24px; margin-right: 10px;">🦖</span>TRICERA AUDIT ENGINE v5.3 — FULL CAPABILITY REPORT</div>
            <h1 class="title">Executive Risk Brief v5.3</h1>
            <div class="metadata-grid">
                <div class="metadata-item"><div class="metadata-label">Activo</div><div class="metadata-val">{{.EliteStats.Hostname}}</div></div>
                <div class="metadata-item"><div class="metadata-label">Modelo</div><div class="metadata-val">{{.EliteStats.Model}}</div></div>
                <div class="metadata-item"><div class="metadata-label">Serie</div><div class="metadata-val">{{.EliteStats.Serial}}</div></div>
                <div class="metadata-item"><div class="metadata-label">Fecha</div><div class="metadata-val">{{.EliteStats.AnalysisDate}}</div></div>
                <div class="metadata-item"><div class="metadata-label">Duración</div><div class="metadata-val">{{.AuditDuration}}</div></div>
            </div>
        </div>

        <!-- 1. RESUMEN EJECUTIVO DE COBERTURA -->
        <div id="coverage" class="section-title">📊 Resumen Ejecutivo de Cobertura de Auditoría</div>
        <div class="coverage-grid">
            <div class="coverage-card">
                <div class="coverage-title">🖥️ Inventario del Activo</div>
                <p style="font-size:12px; color:var(--text-dim); margin-bottom:15px; line-height:1.4;">Muestra los componentes estructurales del equipo. Las interfaces y VLANs determinan el grado de segmentación interna física o lógica.</p>
                <table class="stats-table">
                    <tr><td>Firmware / Build</td><td>{{.EliteStats.FirmwareVersion}} (Build {{.EliteStats.Build}})</td></tr>
                    <tr><td>VDOMs Detectados</td><td>{{.EliteStats.VDOMCount}}</td></tr>
                    <tr><td>Alta Disponibilidad (HA)</td><td>{{if .EliteStats.HADetected}}<span class="tag tag-active">Sí</span>{{else}}<span class="tag tag-inactive">No</span>{{end}}</td></tr>
                    <tr><td>SD-WAN Detectado</td><td>{{if .EliteStats.SDWANDetected}}<span class="tag tag-active">Sí</span>{{else}}<span class="tag tag-inactive">No</span>{{end}}</td></tr>
                    <tr><td>Políticas Firewall</td><td>{{.EliteStats.FirewallPolicyCount}} <a href="#fw-intel" class="link-detail">Rastrear ↗</a></td></tr>
                    <tr><td>Interfaces / VLANs</td><td>{{.EliteStats.InterfaceCount}}</td></tr>
                </table>
                <details style="margin-top:15px; font-size:11.5px; opacity:0.8;">
                    <summary style="cursor:pointer; color:var(--primary); font-weight:700;">🔍 Ver Listado de Interfaces & VLANs</summary>
                    <ul style="margin-top:8px; padding-left:15px; max-height:120px; overflow-y:auto; line-height:1.4; text-align:left;">
                        {{range .EliteStats.VLANsList}}
                        <li>{{.}}</li>
                        {{end}}
                    </ul>
                </details>
            </div>
            <div class="coverage-card">
                <div class="coverage-title">🛠️ Cobertura Técnica del Parser</div>
                <p style="font-size:12px; color:var(--text-dim); margin-bottom:15px; line-height:1.4;">Elementos de seguridad procesados. Los Perfiles de Seguridad representan las inspecciones UTM activas (ej. Antivirus, IPS, Filtrado Web).</p>
                <table class="stats-table">
                    <tr><td>Líneas Procesadas</td><td>{{.EliteStats.LinesProcessed}}</td></tr>
                    <tr><td>Objetos de Dirección</td><td>{{.EliteStats.AddressObjectCount}} <a href="#obj-hygiene" class="link-detail">Rastrear ↗</a></td></tr>
                    <tr><td>Usuarios Administradores</td><td>{{.EliteStats.AdminUserCount}} <a href="#cis-hardening" class="link-detail">Rastrear ↗</a></td></tr>
                    <tr><td>Local-In Policies</td><td>{{.EliteStats.LocalInPolicyCount}} <a href="#localin-analysis" class="link-detail">Rastrear ↗</a></td></tr>
                    <tr><td>Perfiles de Seguridad</td><td>{{.EliteStats.SecurityProfileCount}}</td></tr>
                    <tr><td>Vulnerabilidades Aplicables</td><td>{{.EliteStats.PSIRTApplicable}} <a href="#psirt-full" class="link-detail">Rastrear ↗</a></td></tr>
                </table>
                <details style="margin-top:15px; font-size:11.5px; opacity:0.8;">
                    <summary style="cursor:pointer; color:var(--primary); font-weight:700;">🔍 Ver Listado de Perfiles UTM Detectados</summary>
                    <ul style="margin-top:8px; padding-left:15px; max-height:120px; overflow-y:auto; line-height:1.4; text-align:left;">
                        {{range .EliteStats.SecurityProfilesList}}
                        <li>{{.}}</li>
                        {{end}}
                    </ul>
                </details>
            </div>
        </div>

        <!-- 2. EXECUTIVE SNAPSHOT -->
        <div class="section-title">⚡ Executive Snapshot</div>
        <div class="snapshot-grid">
            <div class="snapshot-card" style="display: flex; gap: 20px; align-items: center; padding: 20px 30px;">
                <div>
                    <svg width="80" height="80" viewBox="0 0 100 100" class="neon-glow">
                        <circle cx="50" cy="50" r="40" stroke="rgba(255, 255, 255, 0.05)" stroke-width="8" fill="none" />
                        <circle cx="50" cy="50" r="40" stroke="var(--cyber-neon)" stroke-width="8" fill="none" stroke-dasharray="250" stroke-dashoffset="60" stroke-linecap="round" transform="rotate(-90 50 50)" />
                        <text x="50" y="55" font-family="'Outfit', sans-serif" font-weight="800" font-size="18" fill="#f8fafc" text-anchor="middle">CRIT</text>
                    </svg>
                </div>
                <div>
                    <div class="snap-label" style="margin-bottom: 5px;">Riesgo Global</div>
                    <div class="snap-val" style="color:var(--cyber-neon); font-size: 20px;">🛡️ Crítico / Activo</div>
                    <div class="snap-desc" style="font-size: 12px;">Riesgos de explotación inmediatos detectados por CISA KEV y PSIRT.</div>
                </div>
            </div>
            <div class="snapshot-card">
                <div class="snap-label">Higiene de Red</div>
                <div class="snap-val">🛡️ {{.EliteStats.HygieneScore}}/100</div>
                <div class="snap-desc">Nivel: <strong>{{.EliteStats.HygieneLevel}}</strong>. Basado en segmentación, objetos y exposición.</div>
            </div>
            <div class="snapshot-card">
                <div class="snap-label">Resiliencia de Red</div>
                <div class="snap-val" style="color:var(--primary)">🔌 {{.EliteStats.ResilienceScore}}/100</div>
                <div class="snap-desc">Medición de Alta Disponibilidad (HA), backups, logs y redundancia de interfaces.</div>
            </div>
            <div class="snapshot-card">
                <div class="snap-label">Cumplimiento GRC</div>
                <div class="snap-val" style="color:var(--warn)">⚖️ Dashboard</div>
                <div class="snap-desc">ISO 27001 ({{percent .Compliance.ISO27001}}), NIST ({{percent .Compliance.NIST}}), PCI ({{percent .Compliance.PCI}}).</div>
            </div>
        </div>

        <!-- 2.5 MITRE ATT&CK FRAMEWORK MAPPING -->
        <div id="mitre-attack-map" class="section-title">🛡️ MITRE ATT&CK Matrix Mapping (Tácticas y Técnicas)</div>
        <div class="ciso-tooltip">
            <strong>💡 Business Impact:</strong> Mapear las configuraciones del firewall contra la matriz de <strong>MITRE ATT&CK</strong> permite a los analistas de SOC e ingenieros de seguridad comprender cómo las fallas identificadas se traducen en vectores reales utilizados por ciberamenazas avanzadas en cada fase del ciclo de vida del ataque.
        </div>
        <div class="mitre-grid">
            <div class="mitre-column" id="mitre-initial-access" onmouseover="highlightMitre('initial-access')">
                <div class="mitre-header">🔑 Acceso Inicial</div>
                <div class="mitre-card crit">
                    <strong>Exposición de VPN / HTTPS</strong>
                    <span style="display:block; opacity:0.8; margin-top:2px;">Planos administrativos expuestos a la WAN pública.</span>
                    <span class="mitre-tech-id">T1190 - Exploit Public-Facing App</span>
                </div>
            </div>
            <div class="mitre-column" id="mitre-execution" onmouseover="highlightMitre('execution')">
                <div class="mitre-header">⚡ Ejecución</div>
                <div class="mitre-card crit">
                    <strong>Vulnerabilidades PSIRT RCE</strong>
                    <span style="display:block; opacity:0.8; margin-top:2px;">Fallos críticos activos por versión de firmware.</span>
                    <span class="mitre-tech-id">T1203 - Exploitation for Client Execution</span>
                </div>
            </div>
            <div class="mitre-column" id="mitre-persistence" onmouseover="highlightMitre('persistence')">
                <div class="mitre-header">🧬 Persistencia</div>
                <div class="mitre-card crit">
                    <strong>Cuentas super_admin</strong>
                    <span style="display:block; opacity:0.8; margin-top:2px;">Cuentas sin protección MFA ni restricción IP.</span>
                    <span class="mitre-tech-id">T1098 - Account Manipulation</span>
                </div>
            </div>
            <div class="mitre-column" id="mitre-defense-evasion" onmouseover="highlightMitre('defense-evasion')">
                <div class="mitre-header">🌑 Evasión de Defensa</div>
                <div class="mitre-card warn">
                    <strong>Logs Desactivados</strong>
                    <span style="display:block; opacity:0.8; margin-top:2px;">Políticas activas sin logs habilitados.</span>
                    <span class="mitre-tech-id">T1562.001 - Impair Defenses</span>
                </div>
            </div>
            <div class="mitre-column" id="mitre-credential-access" onmouseover="highlightMitre('credential-access')">
                <div class="mitre-header">🗝️ Acceso a Credenciales</div>
                <div class="mitre-card crit">
                    <strong>Cifrado Reversible (ENC)</strong>
                    <span style="display:block; opacity:0.8; margin-top:2px;">Credenciales administrativas usando cifrado XOR débil.</span>
                    <span class="mitre-tech-id">T1552 - Unsecured Credentials</span>
                </div>
            </div>
            <div class="mitre-column" id="mitre-discovery" onmouseover="highlightMitre('discovery')">
                <div class="mitre-header">🔍 Descubrimiento</div>
                <div class="mitre-card warn">
                    <strong>Reglas Hiper-Permisivas</strong>
                    <span style="display:block; opacity:0.8; margin-top:2px;">Zonas y políticas any-any sin segmentación adecuada.</span>
                    <span class="mitre-tech-id">T1046 - Network Service Scanning</span>
                </div>
            </div>
        </div>

        <!-- 3. COMPLIANCE MAPPING (GRC Dashboard) -->
        <div id="compliance" class="section-title">⚖️ Compliance Mapping (GRC Dashboard)</div>
        <div class="card">
            <div class="coverage-grid" style="grid-template-columns: repeat(3, 1fr);">
                <div class="coverage-card">
                    <div class="coverage-title">ISO 27001:2022</div>
                    <table class="stats-table">
                        <tr><td>Mapeados</td><td>{{.EliteStats.ISOControlsMapped}}</td></tr>
                        <tr><td>PASADOS</td><td>{{.EliteStats.ISOPass}}</td></tr>
                        <tr><td>FALLIDOS</td><td>{{.EliteStats.ISOFail}}</td></tr>
                        <tr><td>CUMPLIMIENTO</td><td><strong>{{perc .EliteStats.ISOPass .EliteStats.ISOControlsMapped}}</strong></td></tr>
                    </table>
                    {{if .Compliance.FailedISO}}
                    <div style="margin-top:20px; padding-top:15px; border-top:1px solid rgba(255,255,255,0.05);">
                        <h5 style="color:var(--danger); margin-bottom:10px; font-size:12px;">❌ Controles Incumplidos:</h5>
                        <ul style="font-size:11px; opacity:0.8; padding-left:15px; line-height:1.6;">
                            {{range .Compliance.FailedISO}}
                            <li style="margin-bottom:5px;"><strong>{{.ISO27001}}</strong>: {{.Title}}</li>
                            {{end}}
                        </ul>
                    </div>
                    {{end}}
                </div>
                <div class="coverage-card">
                    <div class="coverage-title">NIST CSF 2.0</div>
                    <table class="stats-table">
                        <tr><td>Mapeados</td><td>{{.EliteStats.NISTControlsMapped}}</td></tr>
                        <tr><td>PASADOS</td><td>{{.EliteStats.NISTPass}}</td></tr>
                        <tr><td>FALLIDOS</td><td>{{.EliteStats.NISTFail}}</td></tr>
                        <tr><td>CUMPLIMIENTO</td><td><strong>{{perc .EliteStats.NISTPass .EliteStats.NISTControlsMapped}}</strong></td></tr>
                    </table>
                    {{if .Compliance.FailedNIST}}
                    <div style="margin-top:20px; padding-top:15px; border-top:1px solid rgba(255,255,255,0.05);">
                        <h5 style="color:var(--danger); margin-bottom:10px; font-size:12px;">❌ Controles Incumplidos:</h5>
                        <ul style="font-size:11px; opacity:0.8; padding-left:15px; line-height:1.6;">
                            {{range .Compliance.FailedNIST}}
                            <li style="margin-bottom:5px;"><strong>{{.NIST}}</strong>: {{.Title}}</li>
                            {{end}}
                        </ul>
                    </div>
                    {{end}}
                </div>
                <div class="coverage-card">
                    <div class="coverage-title">PCI-DSS v4.0</div>
                    <table class="stats-table">
                        <tr><td>Mapeados</td><td>{{.EliteStats.PCIControlsMapped}}</td></tr>
                        <tr><td>PASADOS</td><td>{{.EliteStats.PCIPass}}</td></tr>
                        <tr><td>FALLIDOS</td><td>{{.EliteStats.PCIFail}}</td></tr>
                        <tr><td>CUMPLIMIENTO</td><td><strong>{{perc .EliteStats.PCIPass .EliteStats.PCIControlsMapped}}</strong></td></tr>
                    </table>
                    {{if .Compliance.FailedPCI}}
                    <div style="margin-top:20px; padding-top:15px; border-top:1px solid rgba(255,255,255,0.05);">
                        <h5 style="color:var(--danger); margin-bottom:10px; font-size:12px;">❌ Controles Incumplidos:</h5>
                        <ul style="font-size:11px; opacity:0.8; padding-left:15px; line-height:1.6;">
                            {{range .Compliance.FailedPCI}}
                            <li style="margin-bottom:5px;"><strong>{{.PCI}}</strong>: {{.Title}}</li>
                            {{end}}
                        </ul>
                    </div>
                    {{end}}
                </div>
            </div>
        </div>

        <!-- 2.4 SELECTOR DE DISPOSITIVOS PARA AUDITORÍAS MULTI-SUCURSAL -->
        {{if gt (len .Devices) 1}}
        <div class="card" style="margin-bottom: 40px; padding: 25px; border-left: 8px solid var(--primary); display: flex; align-items: center; justify-content: space-between; gap: 20px;">
            <div>
                <h4 style="margin-bottom:5px; display:flex; align-items:center; gap:8px;">📍 Selector de Dispositivo / Sucursal</h4>
                <p style="font-size:12.5px; opacity:0.8;">Auditoría masiva de sucursales detectada. Selecciona una sucursal para desplegar su topología, políticas y cuentas administrativas:</p>
            </div>
            <div>
                <select id="device-selector" onchange="switchDevice(this.value)" style="background:var(--bg); color:var(--text); border:1px solid var(--border); border-radius:12px; padding:12px 25px; font-family:'Outfit'; font-size:14px; font-weight:600; cursor:pointer; outline:none; box-shadow: 0 4px 15px rgba(0,0,0,0.2);">
                    {{range .Devices}}
                    <option value="{{.Hostname}}">{{.Hostname}}</option>
                    {{end}}
                </select>
            </div>
        </div>
        {{end}}

        <!-- 2.5 DYNAMIC TOPOLOGY MAP (PILAR 4) -->
        <div id="topology-map" class="section-title">🗺️ Mapa de Topología Dinámica del Firewall</div>
        <div class="card">
            <p style="margin-bottom:20px; font-size:14px; opacity:0.8;">Mapa visual interactivo de VDOMs, interfaces de transporte y flujos de políticas de seguridad generado en tiempo real a partir del árbol de sintaxis abstracta (AST) de la configuración física:</p>
            
            {{if not .Devices}}
            <div style="background:#0f172a; border-radius:16px; border:1px solid var(--border); padding:25px; overflow:auto; display:flex; justify-content:center;">
                <pre class="mermaid">
graph TD
  Massive[No hay dispositivos de red disponibles]
  style Massive fill:#1e293b,stroke:#38bdf8,stroke-width:2px,color:#f8fafc
                </pre>
            </div>
            {{else}}
                {{range $index, $dev := .Devices}}
                <div class="device-section device-section-{{$dev.Hostname}}" style="{{if gt $index 0}}display:none;{{end}} background:#0f172a; border-radius:16px; border:1px solid var(--border); padding:25px; overflow:auto; display:{{if eq $index 0}}flex{{else}}none{{end}}; justify-content:center;">
                    <pre class="mermaid">
{{$dev.TopologyMermaid}}
                    </pre>
                </div>
                {{end}}
            {{end}}
        </div>

        <!-- 2.6 CONTROL DE IDENTIDAD Y CUENTAS ADMINISTRATIVAS -->
        <div id="iam-inventory" class="section-title">👤 Control de Identidad y Cuentas Administrativas (IAM)</div>
        <div class="ciso-tooltip">
            <strong>💡 Business Impact:</strong> Las normativas internacionales de seguridad (como ISO 27001 control A.9.2.1) exigen mantener un inventario riguroso y formalmente documentado de todas las credenciales de administración autorizadas. Esta sección proporciona una auditoría visual pasiva de las cuentas creadas en el FortiGate para fines de cumplimiento normativo y control interno corporativo.
        </div>
        <div class="card">
            <details>
                <summary style="cursor:pointer; font-weight:800; font-size:16px; color:var(--primary); padding:10px; background:rgba(56, 189, 248, 0.05); border-radius:8px;">Desplegar Inventario Completo de Cuentas Administrativas (IAM)</summary>
                <div style="margin-top:20px;">
                    <p style="margin-bottom:20px; font-size:14px; opacity:0.8;">Cuentas administrativas identificadas activas en la configuración, evaluadas según el cumplimiento de doble factor (MFA) y restricción por origen (Trusted Hosts):</p>
                    
                    {{if not .Devices}}
                    <p style="text-align:center; padding:30px; opacity:0.7;">No hay cuentas administrativas disponibles.</p>
                    {{else}}
                        {{range $index, $dev := .Devices}}
                        <div class="device-section device-section-{{$dev.Hostname}}" style="">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Nombre de Usuario</th>
                                        <th>Perfil de Acceso (Rol)</th>
                                        <th>VDOM Asignado</th>
                                        <th>Estado MFA (2FA)</th>
                                        <th>Restricción de Red (Trusted Hosts)</th>
                                        <th>Línea de Configuración</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {{if not $dev.AdminUsers}}
                                    <tr>
                                        <td colspan="6" style="text-align:center; padding:30px; opacity:0.6; color:var(--text-dim);">
                                            ℹ️ No se identificaron cuentas administrativas personalizadas en esta sucursal.
                                        </td>
                                    </tr>
                                    {{else}}
                                        {{range $dev.AdminUsers}}
                                        <tr>
                                            <td><strong>{{.Name}}</strong></td>
                                            <td>
                                                {{if eq .Profile "super_admin"}}
                                                <span class="badge badge-danger">super_admin (Acceso Total)</span>
                                                {{else}}
                                                <span class="badge badge-info">{{.Profile}}</span>
                                                {{end}}
                                            </td>
                                            <td><code class="evidence-text">{{.VDOM}}</code></td>
                                            <td>
                                                {{if .HasMFA}}
                                                <span class="badge badge-success">Habilitado</span>
                                                {{else}}
                                                <span class="badge badge-danger">INSEGURO: MFA Ausente</span>
                                                {{end}}
                                            </td>
                                            <td>
                                                {{if .HasTrustHost}}
                                                <span class="badge badge-success">Protegido (Trusted Hosts: {{.TrustHosts}})</span>
                                                {{else}}
                                                <span class="badge badge-danger">EXPUSTO: Sin Restricción</span>
                                                {{end}}
                                            </td>
                                            <td style="font-family:'JetBrains Mono'; font-weight:bold;">{{.Line}}</td>
                                        </tr>
                                        {{end}}
                                    {{end}}
                                </tbody>
                            </table>
                        </div>
                        {{end}}
                    {{end}}
                </div>
            </details>
        </div>

        <!-- 3. QUÉ ATENDER PRIMERO -->
        <div id="priorities" class="section-title">🎯 Qué Atender Primero (Top 5 Strategic Actions)</div>
        {{range .ExecActions}}
        <div class="priority-item">
            <div class="priority-p">P1</div>
            <div class="priority-content">
                <h4>{{.Title}}</h4>
                <p style="font-size:14px; opacity:0.8; margin-bottom:10px;">{{.Reason}}</p>
                <div class="evidence-text">Evidencia: {{.Evidence}}</div>
            </div>
            <div class="priority-action">
                <div style="font-weight:800; margin-bottom:5px; color:var(--primary)">REMEDIACIÓN</div>
                <div style="opacity:0.9">{{.Action}}</div>
            </div>
        </div>
        {{end}}

        <!-- 4. PSIRT + KEV + EPSS -->
        <div id="psirt-full" class="section-title">🦠 Priorización y Análisis de Vulnerabilidades (PSIRT)</div>
        
        <div style="margin-top:-30px; margin-bottom:30px; display:flex; gap:10px; align-items:center;">
            <span class="badge {{if eq .PSIRT.IntelStatus "Verificado con FortiGuard Live"}}badge-success{{else if eq .PSIRT.IntelStatus "Resuelto desde catálogo offline embebido"}}badge-info{{else if eq .PSIRT.IntelStatus "Live no disponible; resuelto offline"}}badge-warn{{else}}badge-danger{{end}}" style="font-size:11px; padding:6px 14px; border-radius:20px; text-transform:none; font-weight:700;">
                {{if eq .PSIRT.IntelStatus "Verificado con FortiGuard Live"}}📡 Verificado con FortiGuard Live
                {{else if eq .PSIRT.IntelStatus "Resuelto desde catálogo offline embebido"}}📦 Resuelto desde catálogo offline embebido
                {{else if eq .PSIRT.IntelStatus "Live no disponible; resuelto offline"}}⚠️ Live no disponible; resuelto offline
                {{else}}❌ No verificable: sin datos live ni offline{{end}}
            </span>
        </div>

        {{if .PSIRT.FetchError}}
        <div class="card" style="border-left: 4px solid var(--danger); background: rgba(239, 68, 68, 0.03); margin-bottom: 20px;">
            <div style="font-weight: bold; color: var(--danger); margin-bottom: 8px; font-size: 16px;">
                ⚠️ Advertencia de Inteligencia de Amenazas Offline
            </div>
            <p style="font-size: 14px; margin: 0; line-height: 1.5; opacity: 0.9;">
                El motor de auditoría no pudo conectarse con la base de datos viva de <strong>FortiGuard PSIRT</strong> debido a un error de red o de proxy en el entorno:<br>
                <code style="background: rgba(0,0,0,0.25); padding: 4px 8px; border-radius: 4px; display: inline-block; margin-top: 8px; font-family: monospace; font-size: 12px; color: var(--danger);">{{.PSIRT.FetchError}}</code>
            </p>
            <p style="font-size: 13.5px; margin-top: 12px; opacity: 0.8; line-height: 1.4;">
                <strong>Recomendación:</strong> Si su servidor o estación de trabajo requiere el uso de un proxy corporativo para acceder a internet, asegúrese de configurar las variables de entorno estándar del sistema (<code>HTTP_PROXY</code> / <code>HTTPS_PROXY</code>). El motor de Tricera ahora soporta automáticamente la detección de proxies de red para estas consultas externas.
            </p>
        </div>
        {{else}}
        <!-- PANELES DE PRIORIZACIÓN GRC ESTRATÉGICA -->
        <div class="grc-pill-container">
            <div class="grc-pill">
                <div class="grc-pill-num" style="color:var(--danger)">{{.EliteStats.PSIRTExposureConfirmed}}</div>
                <div class="grc-pill-label">Exposición Activa (Crítico)</div>
            </div>
            <div class="grc-pill">
                <div class="grc-pill-num" style="color:var(--success)">{{.EliteStats.PSIRTNotApplicable}}</div>
                <div class="grc-pill-label">Mitigadas por Configuración</div>
            </div>
            <div class="grc-pill">
                <div class="grc-pill-num" style="color:var(--warn)">{{.EliteStats.PSIRTManualReview}}</div>
                <div class="grc-pill-label">Requieren Revisión Manual</div>
            </div>
            <div class="grc-pill">
                <div class="grc-pill-num" style="color:var(--info)">{{.EliteStats.PSIRTVersionOnly}}</div>
                <div class="grc-pill-label">Potenciales por Versión</div>
            </div>
        </div>

        <div class="card">
            <p style="margin-bottom:20px; font-size:14px; opacity:0.8;">Lista completa de boletines de seguridad de FortiGuard (PSIRT) aplicables a la versión del firmware. El motor ha priorizado y filtrado cada vulnerabilidad según la exposición real de la configuración activa:</p>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Prioridad</th>
                        <th>PSIRT ID / CVE</th>
                        <th>Severidad</th>
                        <th>EPSS / KEV</th>
                        <th>Estado / Exposición Real</th>
                        <th>Línea / Evidencia de Exposición</th>
                        <th>Acción Inmediata</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .EnrichedPSIRT}}
                    <tr {{if .IsCisaKEV}}style="background:rgba(239, 68, 68, 0.03)"{{end}}>
                        <td><strong style="color:var(--danger)">{{.TriceraPriority}}</strong><br><small>{{.TTPScore}}/100</small></td>
                        <td>
                            <strong>{{.PSIRTID}}</strong><br>
                            <small>{{.CVE}}</small><br>
                            <span style="font-size:10px; opacity:0.6; display:inline-block; margin-top:4px;">
                                {{if eq .IntelSource "Verificado con FortiGuard Live"}}📡 Live
                                {{else if eq .IntelSource "Resuelto desde catálogo offline embebido"}}📦 Offline
                                {{else if eq .IntelSource "Live no disponible; resuelto offline"}}⚠️ Resguardo
                                {{else}}❌ Sin datos{{end}}
                            </span>
                        </td>
                        <td><span class="badge {{if eq .VendorSeverity "Critical"}}badge-danger{{else}}badge-warn{{end}}">{{.VendorSeverity}}</span></td>
                        <td>{{percent .EPSSScore}}<br>{{if .IsCisaKEV}}<span class="badge badge-danger" style="margin-top:5px;">CISA KEV</span>{{end}}</td>
                        <td>
                            {{if eq .ExploitStatus "Activo / Expuesto"}}
                            <span class="badge-danger-glow">⚠️ Activo / Expuesto</span>
                            {{else if eq .ExploitStatus "Mitigado por Configuración"}}
                            <span class="badge-success-glow">🛡️ Mitigado por Configuración</span>
                            {{else if eq .ExploitStatus "Revisión Manual"}}
                            <span class="badge-warn-glow">🔍 Revisión Manual</span>
                            {{else}}
                            <span class="badge-info-glow">ℹ️ Potencial por Versión</span>
                            {{end}}
                        </td>
                        <td><div class="evidence-text">{{.EvidenceSummary}}</div></td>
                        <td><div style="font-size:11.5px; opacity:0.95;">{{.ImmediateAction}}</div></td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}

        <!-- 5. LOCAL-IN ANALYSIS -->
        <div id="localin-analysis" class="section-title">🛡️ Local-In Policy Analysis</div>
        <div class="ciso-tooltip">
            <strong>💡 Business Impact:</strong> Los ataques dirigidos contra FortiGate casi siempre apuntan a los servicios administrativos expuestos (como SSL-VPN o HTTPS). Las Local-In Policies actúan como un escudo primario bloqueando IPs maliciosas de internet <i>antes</i> de que alcancen el sistema de autenticación corporativo, previniendo CVEs.
        </div>
        <div class="card">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Interfaz / VDOM</th>
                        <th>Línea</th>
                        <th>Acceso Permitido</th>
                        <th>Local-In</th>
                        <th>Riesgo Detectado</th>
                        <th>Acción Sugerida</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .FindingGroups}}
                        {{if eq .GroupID "INT-LOCALIN-01"}}
                            {{range .AffectedItems}}
                            <tr>
                                <td><strong>{{.Name}}</strong><br><small>{{.VDOM}}</small></td>
                                <td>{{.Line}}</td>
                                <td><code class="evidence-text">{{.Value}}</code></td>
                                <td><span class="badge badge-danger">No Detectada</span></td>
                                <td>Exposición del plano de gestión</td>
                                <td>Implementar Local-In Policy restrictiva</td>
                            </tr>
                            {{end}}
                        {{end}}
                    {{end}}
                </tbody>
            </table>
        </div>

        <!-- 6. FIREWALL POLICY INTELLIGENCE -->
        <div id="fw-intel" class="section-title">🕵️ Firewall Policy Intelligence</div>
        {{range $group := .FindingGroups}}
            {{if eq $group.Category "FW-INTEL"}}
            <div class="card">
                <div style="display:flex; justify-content:space-between; margin-bottom:15px;">
                    <h3>{{$group.Title}}</h3>
                    <span class="badge badge-danger">{{$group.Severity}}</span>
                </div>
                <div style="background:rgba(245, 158, 11, 0.05); padding:15px; border-left:3px solid var(--warn); border-radius:4px; margin-bottom:20px; font-size:13px; color:var(--text-dim);">
                    <strong style="color:var(--warn)">💼 Business Impact:</strong> {{$group.BusinessImpact}}
                </div>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Policy ID / VDOM</th>
                            <th>Línea</th>
                            <th>Configuración Detectada</th>
                            <th>Acción Recomendada</th>
                            <th>Remediación Rápida CLI</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range $group.AffectedItems}}
                        <tr>
                            <td><strong>ID: {{.PolicyID}}</strong><br><small>{{.VDOM}}</small></td>
                            <td>{{.Line}}</td>
                            <td><code class="evidence-text">{{.Evidence}}</code></td>
                            <td>{{$group.Recommendation}}</td>
                            <td>
                                {{if .RemediationCLI}}
                                <pre style="font-family:'JetBrains Mono'; font-size:10px; background:#0f172a; padding:8px; border-radius:4px; border:1px solid rgba(16, 185, 129, 0.2); color:var(--primary); margin:0; text-align:left;">{{.RemediationCLI}}</pre>
                                {{else}}
                                <span style="opacity:0.5; font-size:11px;">Consolidación manual de objetos</span>
                                {{end}}
                            </td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
            {{end}}
        {{end}}

        <!-- 7. SHADOW RULES -->
        <div id="shadow-rules" class="section-title">🌑 Shadow Rules Analysis</div>
        <div class="ciso-tooltip">
            <strong>💡 Business Impact:</strong> Las "Reglas en la Sombra" son políticas que nunca reciben tráfico porque una regla superior bloquea o permite ese flujo antes. Representan deuda técnica severa, complican las auditorías normativas y pueden causar que aperturas críticas no funcionen, prolongando caídas de servicio (Downtime).
        </div>
        <div class="card">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Policy ID / VDOM</th>
                        <th>Línea</th>
                        <th>Evidencia de Sombreado</th>
                        <th>Riesgo</th>
                        <th>Acción</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .FindingGroups}}
                        {{if eq .GroupID "INT-SHADOW-01"}}
                            {{range .AffectedItems}}
                            <tr>
                                <td><strong>ID: {{.PolicyID}}</strong><br><small>{{.VDOM}}</small></td>
                                <td>{{.Line}}</td>
                                <td><code class="evidence-text">{{.Evidence}}</code></td>
                                <td>Inalcanzabilidad de regla / Deuda técnica</td>
                                <td>Eliminar regla o reordenar</td>
                            </tr>
                            {{end}}
                        {{end}}
                    {{end}}
                </tbody>
            </table>
        </div>

        <!-- 7.5 INVENTARIO COMPLETO DE POLÍTICAS DE FIREWALL AUDITADAS -->
        <div id="policy-inventory" class="section-title">📊 Inventario Completo de Políticas de Firewall Auditadas</div>
        
        {{if not .Devices}}
        <div class="card"><p style="text-align:center; padding:30px; opacity:0.7;">No hay políticas disponibles.</p></div>
        {{else}}
            {{range $index, $dev := .Devices}}
            <div class="device-section device-section-{{$dev.Hostname}}" style="{{if gt $index 0}}display:none;{{end}}">
                <div class="card" style="max-height: 500px; overflow-y: auto;">
                    <p style="margin-bottom:20px; font-size:14px; opacity:0.8;">Inventario exhaustivo de todas las políticas de firewall activas e inactivas procesadas en la configuración de la sucursal <strong>{{$dev.Hostname}}</strong>.<br><em style="color:var(--warn); font-size:12px;">Nota: Solo se listan reglas explícitas de capa 4 (IPv4/IPv6). El Parser Tricera no extrae reglas implícitas o propias del sistema operativo, por lo que el conteo puede ser menor al de la GUI gráfica.</em></p>
                    <table class="data-table">
                        <thead style="position: sticky; top: 0; background: var(--surface); z-index: 10;">
                            <tr>
                                <th>ID / Nombre</th>
                                <th>VDOM</th>
                                <th>Estado</th>
                                <th>Interfaz Origen / Destino</th>
                                <th>Dirección Origen / Destino</th>
                                <th>Servicio</th>
                                <th>Acción</th>
                                <th>Registro (Log)</th>
                                <th>Línea</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{if not $dev.Policies}}
                            <tr>
                                <td colspan="9" style="text-align:center; padding:30px; opacity:0.6; color:var(--text-dim);">
                                    ℹ️ No se identificaron políticas de firewall explícitas en esta sucursal.
                                </td>
                            </tr>
                            {{else}}
                                {{range $dev.Policies}}
                                <tr>
                                    <td><strong>ID: {{.ID}}</strong>{{if .Name}}<br><small style="color:var(--primary)">{{.Name}}</small>{{end}}</td>
                                    <td><code class="evidence-text">{{.VDOM}}</code></td>
                                    <td>
                                        {{if eq .Status "enable"}}
                                        <span class="badge badge-success">Activa</span>
                                        {{else}}
                                        <span class="badge badge-info" style="opacity:0.5;">Deshabilitada</span>
                                        {{end}}
                                    </td>
                                    <td>
                                        <div style="font-size:11px;">
                                            <strong>De:</strong> {{range .SrcIntf}}{{.}} {{end}}<br>
                                            <strong>A:</strong> {{range .DstIntf}}{{.}} {{end}}
                                        </div>
                                    </td>
                                    <td>
                                        <div style="font-size:11px;">
                                            <strong>Orig:</strong> {{range .SrcAddr}}{{.}} {{end}}<br>
                                            <strong>Dest:</strong> {{range .DstAddr}}{{.}} {{end}}
                                        </div>
                                    </td>
                                    <td>
                                        <div style="font-size:11px; font-family:'JetBrains Mono';">
                                            {{range .Service}}{{.}} {{end}}
                                        </div>
                                    </td>
                                    <td>
                                        {{if eq .Action "accept"}}
                                        <span class="tag tag-active" style="background:rgba(16, 185, 129, 0.15)">ACCEPT</span>
                                        {{else}}
                                        <span class="tag tag-inactive" style="background:rgba(239, 68, 68, 0.15); color:var(--danger); border-color:var(--danger)">DENY</span>
                                        {{end}}
                                    </td>
                                    <td>
                                        {{if or (eq .Logging "all") (eq .Logging "utm")}}
                                        <span class="badge badge-success">Todo</span>
                                        {{else}}
                                        <span class="badge badge-danger">Desactivado</span>
                                        {{end}}
                                    </td>
                                    <td style="font-family:'JetBrains Mono'; font-weight:bold;">{{.Line}}</td>
                                </tr>
                                {{end}}
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
            {{end}}
        {{end}}

        <!-- 8. OBJECT HYGIENE -->
        <div id="obj-hygiene" class="section-title">🧹 Object Hygiene & Health</div>
        <div class="ciso-tooltip">
            <strong>💡 Business Impact:</strong> Mantener una higiene estricta evita la degradación del rendimiento del firewall y deudas técnicas. Los <strong>Servicios Personalizados</strong> son puertos no estándar que a menudo se usan para evadir controles corporativos (ej. P2P o minería). Los <strong>Objetos Huérfanos</strong> son reglas abandonadas que consumen memoria RAM y complican auditorías normativas.
        </div>
        {{range .FindingGroups}}
            {{if or (eq .Category "OBJ-HYGIENE") (eq .Category "HIGIENE")}}
            <div class="card">
                <div style="display:flex; justify-content:space-between; margin-bottom:15px;">
                    <h4>{{.Title}}</h4>
                    <span class="badge badge-info">{{.AffectedCount}} Items</span>
                </div>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Objeto / VDOM</th>
                            <th>Línea</th>
                            <th>Tipo / Valor</th>
                            <th>Acción</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .AffectedItems}}
                        <tr>
                            <td><strong>{{.Name}}</strong><br><small>{{.VDOM}}</small></td>
                            <td>{{.Line}}</td>
                            <td>{{.Evidence}}</td>
                            <td>Depurar / Consolidar</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
            {{end}}
        {{end}}

        <!-- 10. CIS HARDENING DETALLE -->
        <div id="cis-hardening" class="section-title">⚙️ Endurecimiento de Seguridad de la Plataforma (Línea Base CIS)</div>
        <div class="ciso-tooltip">
            <strong>💡 Business Impact:</strong> El estándar CIS (Center for Internet Security) es el marco de endurecimiento (hardening) más respetado del mundo. Aplicar sus controles cierra brechas lógicas críticas en el plano operativo y reduce la superficie de explotación ante ataques automatizados y persistentes.
        </div>
        {{range .TechnicalCIS}}
        <div class="card" style="background: transparent; border: none; padding: 0;">
            <div style="display:flex; justify-content:space-between; margin-bottom:20px; padding: 0 10px;">
                <h3 style="font-size:24px;">{{.Icon}} {{.Name}}</h3>
                <span class="badge badge-warn" style="font-size:14px; padding:8px 16px;">{{len .Findings}} Riesgos Detectados</span>
            </div>
            
            {{range .Findings}}
            <div class="risk-card">
                <div class="risk-header">
                    <div class="risk-title">
                        <span class="risk-id">{{.ID}}</span> 
                        {{.Title}}
                    </div>
                    <span class="badge {{if eq .ImpactLevel "C"}}badge-danger{{else if eq .ImpactLevel "H"}}badge-warn{{else}}badge-info{{end}}">Severidad: {{.ImpactLevel}}</span>
                </div>
                
                <div class="impact-grid">
                    <div class="impact-box biz">
                        <div class="impact-title" style="color:var(--warn)">💼 Impacto en el Negocio</div>
                        <div class="impact-text">{{if .BusinessImpact}}{{.BusinessImpact}}{{else}}Vulnerabilidad operativa que compromete el cumplimiento y la disponibilidad del servicio.{{end}}</div>
                    </div>
                    <div class="impact-box tech">
                        <div class="impact-title" style="color:var(--primary)">🛠️ Impacto Técnico</div>
                        <div class="impact-text">{{if .TechnicalImpact}}{{.TechnicalImpact}}{{else}}Configuración insegura detectada en el plano de control o de datos.{{end}}</div>
                    </div>
                </div>

                <div style="font-size:11px; color:var(--text-dim); margin-bottom:5px; text-transform:uppercase; letter-spacing:1px;">Evidencia Técnica (Línea {{.Line}} - VDOM: {{.VDOM}})</div>
                <div class="risk-evidence">
                    {{if .FailedPath}}
                    > Ruta: <code style="color:var(--primary)">{{.FailedPath}}</code><br>
                    > Valor detectado: <code style="color:var(--warn)">{{.Value}}</code>
                    {{else}}
                    <span style="color:var(--danger); font-weight:700;">⚠️ Ausencia de Configuración Activa:</span> {{.Evidence}}
                    {{end}}
                </div>
                
                <div class="risk-action">
                    <span style="font-size:22px;">🎯</span>
                    <div>
                        <div style="font-size:11px; font-weight:800; color:var(--success); text-transform:uppercase; margin-bottom:2px;">Plan de Remediación Sugerido</div>
                        <div style="font-size:13px; opacity:0.9;">{{.Remediation}}</div>
                    </div>
                </div>
            </div>
            {{end}}
        </div>
        {{end}}

        <!-- 11. APÉNDICE TÉCNICO -->
        <div id="appendix" class="section-title">📑 Apéndice Técnico de Evidencias (Master List)</div>
        <div class="ciso-tooltip" style="border-left: 3px solid var(--text-dim); background: rgba(255,255,255,0.02);">
            <strong>💡 Nota Técnica:</strong> Esta sección es de carácter puramente operativo y forense. Está diseñada exclusivamente para los ingenieros de red y administradores de sistemas como guía de referencia rápida para ubicar y validar físicamente las líneas de configuración brutas del archivo analizado.
        </div>
        <div class="card">
            <details>
                <summary style="cursor:pointer; font-weight:800; font-size:16px; color:var(--primary); padding:10px; background:rgba(56, 189, 248, 0.05); border-radius:8px;">Desplegar Lista Completa de Evidencias Brutas</summary>
                <div style="margin-top:20px;">
            <table class="data-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Entidad</th>
                        <th>VDOM</th>
                        <th>Línea</th>
                        <th>Evidencia Bruta</th>
                        <th>QuickFix CLI</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .TechnicalCIS}}
                        {{range .Findings}}
                        <tr>
                            <td><strong>{{.ID}}</strong></td>
                            <td>{{.DeviceName}}</td>
                            <td>{{.VDOM}}</td>
                            <td>{{.Line}}</td>
                            <td><code class="evidence-text">{{.Evidence}}</code></td>
                            <td>
                                {{if .CLIScript}}
                                <div class="cli-box" style="margin-top:0;">
                                    <span class="cli-label">DINÁMICO</span>
                                    <pre style="margin:0; white-space:pre-wrap; font-family: 'JetBrains Mono', monospace; font-size: 11px;">{{.CLIScript}}</pre>
                                </div>
                                {{else if .QuickFix}}
                                <div class="cli-box" style="margin-top:0; border-color: rgba(245, 158, 11, 0.2);">
                                    <span class="cli-label" style="background: var(--warn); color: var(--bg);">GENÉRICO</span>
                                    <pre style="margin:0; white-space:pre-wrap; font-family: 'JetBrains Mono', monospace; font-size: 11px;">{{.QuickFix}}</pre>
                                </div>
                                {{else}}
                                <span style="opacity:0.5;">Manual</span>
                                {{end}}
                            </td>
                        </tr>
                        {{end}}
                    {{end}}
                </tbody>
            </table>
                </div>
            </details>
        </div>

        <footer>
            <div style="font-weight:800; color:var(--primary); margin-bottom:5px">TRICERA AUDIT ENGINE v5.3 — THE FULL PLATFORM</div>
            <div>Postura de Riesgo, Cobertura Técnica, Inteligencia de Amenazas y GRC Dashboard.</div>
            <div style="margin-top:10px; opacity:0.6;">&copy; 2026 StegoSec Intelligence Hub.</div>
        </footer>
    </div>
</body>
</html>
`
