package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	ID               string `json:"id" yaml:"id"`
	Title            string `json:"title" yaml:"title"`
	AffectedVersion  string `json:"affected_version" yaml:"affected_version"`
	TriggerPath      string `json:"trigger_path" yaml:"trigger_path"`
	TriggerValue     string `json:"trigger_value" yaml:"trigger_value"`
	CELExpression    string `json:"cel_expression" yaml:"cel_expression"`
	MitigationPath   string `json:"mitigation_path" yaml:"mitigation_path"`
	Description      string `json:"description" yaml:"description"`
	ImpactLevel      string `json:"impact_level" yaml:"impact_level"`
	Remediation      string `json:"remediation" yaml:"remediation"`
	Workaround       string `json:"workaround" yaml:"workaround"`
	Reference        string `json:"reference" yaml:"reference"`
	Category         string `json:"category" yaml:"category"`
	Operator         string `json:"operator" yaml:"operator"`
	RemediationValue string `json:"remediation_value" yaml:"remediation_value"`
	Section          string `json:"section" yaml:"section"`
	MitreID          string `json:"mitre_id" yaml:"mitre_id"`
	IsExploited      bool   `json:"is_exploited" yaml:"is_exploited"`
	ThreatSource     string `json:"threat_source" yaml:"threat_source"`
	BusinessImpact   string `json:"business_impact" yaml:"business_impact"`
	TechnicalImpact  string `json:"technical_impact" yaml:"technical_impact"`
	ValidationStep   string `json:"validation_step" yaml:"validation_step"`
	ISO27001         string `json:"iso27001" yaml:"iso27001"`
	NIST             string `json:"nist" yaml:"nist"`
	PCI              string `json:"pci" yaml:"pci"`
	QuickFix         string `json:"quick_fix" yaml:"quick_fix"`
}

// SEC-FIX A-03: Límite de tamaño para archivos de reglas externas
const maxRulesFileSize = 10 * 1024 * 1024 // 10MB

func LoadRules(path string) ([]Rule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxRulesFileSize {
		return nil, fmt.Errorf("archivo de reglas excede el límite de %dMB", maxRulesFileSize/(1024*1024))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	
	var rules []Rule
	lowerPath := strings.ToLower(path)
	
	// Detectar si el archivo es YAML
	if strings.HasSuffix(lowerPath, ".yaml") || strings.HasSuffix(lowerPath, ".yml") {
		if err := yaml.Unmarshal(data, &rules); err != nil {
			return nil, err
		}
		return rules, nil
	}
	
	// Por defecto descodificar como JSON para mantener retrocompatibilidad
	if err := json.Unmarshal(data, &rules); err != nil {
		return nil, err
	}
	return rules, nil
}
