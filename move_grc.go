package main

import (
	"fmt"
	"io/ioutil"
	"strings"
)

func main() {
	contentBytes, err := ioutil.ReadFile("internal/report/reporter.go")
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	content := string(contentBytes)

	// Encontrar el bloque GRC
	grcStart := strings.Index(content, "<!-- 9. COMPLIANCE MAPPING -->")
	if grcStart == -1 {
		fmt.Println("GRC block not found")
		return
	}

	grcEndStr := "</div>\n                </div>\n            </div>\n        </div>"
	grcEndIndex := strings.Index(content[grcStart:], grcEndStr)
	if grcEndIndex == -1 {
		fmt.Println("GRC end not found")
		return
	}
	grcEnd := grcStart + grcEndIndex + len(grcEndStr)

	grcBlock := content[grcStart:grcEnd]
	
	// Eliminar el bloque original
	contentWithoutGrc := content[:grcStart] + content[grcEnd:]

	// Insertar después de EXECUTIVE SNAPSHOT
	snapEndStr := "</div>\n        </div>\n\n        <!-- 2.4"
	snapEnd := strings.Index(contentWithoutGrc, snapEndStr)
	if snapEnd == -1 {
		fmt.Println("Snapshot end not found")
		return
	}
	insertPos := snapEnd + 15 // just before <!-- 2.4

	newGrcBlock := strings.Replace(grcBlock, "<!-- 9. COMPLIANCE MAPPING -->", "<!-- 3. COMPLIANCE MAPPING (GRC Dashboard) -->", 1)

	finalContent := contentWithoutGrc[:insertPos] + "\n        " + newGrcBlock + "\n\n" + contentWithoutGrc[insertPos:]

	err = ioutil.WriteFile("internal/report/reporter.go", []byte(finalContent), 0644)
	if err != nil {
		fmt.Println("Error writing file:", err)
		return
	}
	fmt.Println("GRC Block successfully moved!")
}
