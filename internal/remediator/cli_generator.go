package remediator

import (
	"fmt"
	"strings"
	"tricera/internal/parser"
)

// GenerateCLI recibe el nodo raíz del AST y la ruta que falló para generar el script de mitigación
func GenerateCLI(root *parser.ASTNode, failedPath string, targetValue string) string {
	if failedPath == "" {
		return "# Remediación manual requerida: No se pudo determinar la ruta exacta."
	}

	nodes := root.FindPath(failedPath)
	if len(nodes) == 0 {
		return fmt.Sprintf("# Remediación manual requerida para: %s", failedPath)
	}

	// Usamos el primer nodo encontrado para generar el contexto
	node := nodes[0]
	
	var commands []string
	var blocks []string

	// Recorremos hacia arriba para encontrar los bloques 'config' y 'edit'
	curr := node.Parent
	for curr != nil && curr.Type != parser.NodeRoot {
		if curr.Type == parser.NodeConfig {
			blocks = append([]string{fmt.Sprintf("config %s", strings.ReplaceAll(curr.Key, ".", " "))}, blocks...)
		} else if curr.Type == parser.NodeEdit {
			blocks = append([]string{fmt.Sprintf("    edit \"%s\"", curr.Key)}, blocks...)
		}
		curr = curr.Parent
	}

	commands = append(commands, blocks...)

	// SEC-FIX A-05: Sanitizar targetValue para prevenir inyección de comandos desde archivos de reglas
	cleanTarget := strings.ReplaceAll(targetValue, "\n", " ")
	cleanTarget = strings.ReplaceAll(cleanTarget, "\r", "")
	cleanTarget = strings.ReplaceAll(cleanTarget, ";", "")

	// Acción de remediación
	indent := strings.Repeat("    ", len(blocks))
	if cleanTarget == "" || cleanTarget == "*" {
		commands = append(commands, fmt.Sprintf("%sunset %s", indent, node.Key))
	} else {
		commands = append(commands, fmt.Sprintf("%sset %s %s", indent, node.Key, cleanTarget))
	}

	// Cerrar bloques en orden inverso
	curr = node.Parent
	for curr != nil && curr.Type != parser.NodeRoot {
		if curr.Type == parser.NodeEdit {
			commands = append(commands, "    next")
		} else if curr.Type == parser.NodeConfig {
			commands = append(commands, "end")
		}
		curr = curr.Parent
	}

	return strings.Join(commands, "\n")
}
