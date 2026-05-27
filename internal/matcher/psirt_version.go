package matcher

import (
	"tricera/internal/intelligence"
	"tricera/internal/parser"
)

type PSIRTFinding struct {
	Advisory intelligence.Advisory
	State    intelligence.FindingState
}

// MatchAdvisories compara la versión detectada y la configuración con los advisories extraídos
func MatchAdvisories(version string, advisories []intelligence.Advisory, config *parser.FGTConfig) []PSIRTFinding {
	var findings []PSIRTFinding

	for i := range advisories {
		state := CheckExposure(advisories[i], config)
		
		// Construir acción recomendada basada en el estado
		advisories[i].RecommendedAction = BuildRecommendedAction(advisories[i], state)
		
		findings = append(findings, PSIRTFinding{
			Advisory: advisories[i],
			State:    state,
		})
	}

	return findings
}

func BuildRecommendedAction(adv intelligence.Advisory, state intelligence.FindingState) string {
	if adv.IsExploited {
		if state == intelligence.ExposureConfirmed {
			return "Atención inmediata. Validar exposición, buscar indicadores de compromiso (IoC), aplicar workaround oficial si existe y actualizar firmware a versión corregida de forma urgente."
		}
		return "Priorizar actualización de firmware. Aunque no se confirmó exposición en backup, el CVE tiene explotación conocida (CISA KEV) y aplica por versión."
	}

	switch state {
	case intelligence.ExposureConfirmed:
		return "Mitigar componente expuesto, restringir acceso mediante Local In Policy o Trusted Hosts, aplicar hardening específico y programar actualización de firmware."
	case intelligence.ManualReviewRequired:
		return "Validar en operación. El archivo de respaldo no permite confirmar completamente este componente. Se recomienda revisión manual de la configuración activa."
	case intelligence.ApplicableByVersion:
		return "Planificar actualización de firmware según ciclo de mantenimiento corporativo. Revisar mitigaciones oficiales mientras se programa el cambio."
	case intelligence.NotApplicableByConfig:
		return "Mantener en backlog de actualización. Validar que el componente no esté habilitado en producción accidentalmente."
	default:
		return "Consultar advisory oficial para determinar impacto operativo y pasos de mitigación."
	}
}

func GetRecommendation(state intelligence.FindingState, isExploited bool) string {
	// Mantener por compatibilidad o redirigir a BuildRecommendedAction con un dummy
	return BuildRecommendedAction(intelligence.Advisory{IsExploited: isExploited}, state)
}
