package engine

import (
	"strconv"
	"strings"
)

// IsVersionVulnerable compara la versión del dispositivo contra la regla
// Soporta formatos tipo "7.4.1" y operadores ">=", "<=", ">", "<", "=="
func IsVersionVulnerable(deviceVer, ruleVer string) bool {
	if deviceVer == "" || ruleVer == "" {
		return false
	}

	// Separar operador del valor (ej. ">= 7.4.0")
	op := "=="
	target := ruleVer

	ops := []string{">=", "<=", ">", "<", "=="}
	for _, o := range ops {
		if strings.HasPrefix(ruleVer, o) {
			op = o
			target = strings.TrimSpace(strings.TrimPrefix(ruleVer, o))
			break
		}
	}

	v1 := parseVersion(deviceVer)
	v2 := parseVersion(target)

	res := compareVersions(v1, v2)

	switch op {
	case "==":
		return res == 0
	case ">=":
		return res >= 0
	case "<=":
		return res <= 0
	case ">":
		return res > 0
	case "<":
		return res < 0
	}

	return false
}

func parseVersion(v string) []int {
	// Limpiar 'v' inicial si existe
	v = strings.TrimPrefix(strings.ToLower(v), "v")
	parts := strings.Split(v, ".")
	ints := make([]int, 0, 3)
	for _, p := range parts {
		// SEC-FIX VULN-017: Manejar segmentos no numéricos explícitamente
		// Si un segmento contiene texto (ej. "4b"), extraer solo la parte numérica inicial
		p = strings.TrimSpace(p)
		numStr := ""
		for _, c := range p {
			if c >= '0' && c <= '9' {
				numStr += string(c)
			} else {
				break
			}
		}
		if numStr == "" {
			ints = append(ints, 0)
		} else {
			i, _ := strconv.Atoi(numStr)
			ints = append(ints, i)
		}
	}
	// Rellenar hasta 3 partes si falta (ej. "7.4" -> [7, 4, 0])
	for len(ints) < 3 {
		ints = append(ints, 0)
	}
	return ints
}

func compareVersions(v1, v2 []int) int {
	for i := 0; i < 3; i++ {
		if v1[i] > v2[i] {
			return 1
		}
		if v1[i] < v2[i] {
			return -1
		}
	}
	return 0
}
