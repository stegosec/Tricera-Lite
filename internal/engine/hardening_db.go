package engine

import (
	_ "embed"
	"log"

	"gopkg.in/yaml.v3"
)

//go:embed rules.yaml
var defaultRulesData []byte

// GetHardeningRules devuelve los controles críticos de hardening enriquecidos para FortiGate
func GetHardeningRules() []Rule {
	var rules []Rule
	if err := yaml.Unmarshal(defaultRulesData, &rules); err != nil {
		// SEC-FIX A-04: Fallar ruidosamente si las reglas base están corruptas
		log.Fatalf("ERROR CRÍTICO: No se pudieron cargar las reglas base de hardening: %v", err)
	}
	return rules
}
