package engine

import (
	"fmt"
)

type DiffResult struct {
	Added    []CheckResult
	Removed  []CheckResult
	Modified []CheckResult
}

func CompareAudits(oldResults, newResults []CheckResult) DiffResult {
	var diff DiffResult
	
	oldMap := make(map[string]CheckResult)
	for _, r := range oldResults {
		if !r.Passed {
			// SEC-FIX B-05: Usar FailedPath en lugar de Line para evitar falsos positivos si se insertan líneas
			key := fmt.Sprintf("%s-%s-%s", r.ID, r.Section, r.FailedPath)
			oldMap[key] = r
		}
	}

	newMap := make(map[string]CheckResult)
	for _, r := range newResults {
		if !r.Passed {
			// SEC-FIX B-05: Usar FailedPath en lugar de Line para evitar falsos positivos si se insertan líneas
			key := fmt.Sprintf("%s-%s-%s", r.ID, r.Section, r.FailedPath)
			newMap[key] = r
		}
	}

	// 1. Detectar Nuevos Riesgos y Modificados
	for key, newRes := range newMap {
		if oldRes, exists := oldMap[key]; exists {
			if oldRes.Value != newRes.Value {
				diff.Modified = append(diff.Modified, newRes)
			}
		} else {
			diff.Added = append(diff.Added, newRes)
		}
	}

	// 2. Detectar Riesgos Resueltos
	for key, oldRes := range oldMap {
		if _, exists := newMap[key]; !exists {
			diff.Removed = append(diff.Removed, oldRes)
		}
	}

	return diff
}
