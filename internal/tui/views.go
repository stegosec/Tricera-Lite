package tui

import (
	"fmt"
	"strings"
)

func (m Model) View() string {
	if m.quitting {
		return ""
	}

	var s strings.Builder
	s.WriteString(TitleStyle.Render("🦖 Tricera-lite TUI v0.1.1"))
	s.WriteString("\n\n")

	switch m.state {
	case stateFilePicker:
		s.WriteString(SubtitleStyle.Render("Selecciona el archivo .conf de FortiOS a auditar:"))
		s.WriteString("\n\n")
		s.WriteString(m.filepicker.View())
		
		if m.scanError != nil {
			s.WriteString("\n")
			s.WriteString(ErrorStyle.Render(m.scanError.Error()))
		}
		
		s.WriteString("\n\n")
		s.WriteString(DimStyle.Render("↑/k: arriba • ↓/j: abajo • Enter: seleccionar • ←/Backspace: subir • p: escribir ruta absoluta • q: salir"))

	case stateManualPath:
		s.WriteString(SubtitleStyle.Render("Ingresa la ruta absoluta del archivo en tu disco (ej. D:\\carpetas\\archivo.conf):"))
		s.WriteString("\n\n")
		s.WriteString(m.pathInput.View())

		if m.scanError != nil {
			s.WriteString("\n\n")
			s.WriteString(ErrorStyle.Render(m.scanError.Error()))
		}
		
		s.WriteString("\n\n")
		s.WriteString(DimStyle.Render("Enter: continuar • Esc: regresar • q: salir"))

	case stateOptions:
		s.WriteString(SubtitleStyle.Render(fmt.Sprintf("Archivo seleccionado: %s", m.selectedFile)))
		s.WriteString("\n\n")
		s.WriteString(HighlightStyle.Render("Selecciona la fuente de Inteligencia PSIRT:"))
		s.WriteString("\n\n")

		choices := []string{
			"Offline (Rápido, base local embebida)",
			"Live (Consulta FortiGuard APIs, toma varios minutos)",
		}

		for i, choice := range choices {
			cursor := " " 
			if m.cursorOption == i {
				cursor = ">"
				choice = HighlightStyle.Render(choice)
			}
			s.WriteString(fmt.Sprintf("%s %s\n", cursor, choice))
		}
		
		s.WriteString("\n")
		s.WriteString(DimStyle.Render("↑/k: arriba • ↓/j: abajo • Enter: continuar • Esc: regresar • q: salir"))

	case stateReportName:
		s.WriteString(SubtitleStyle.Render("Ingresa el nombre del reporte (la extensión .html se agregará automáticamente):"))
		s.WriteString("\n\n")
		s.WriteString(m.textInput.View())
		s.WriteString("\n\n")
		s.WriteString(DimStyle.Render("Enter: iniciar auditoría • Esc: regresar • q: salir"))

	case stateScanning:
		s.WriteString(HighlightStyle.Render(fmt.Sprintf("👾 ANALIZANDO: %s", m.selectedFile)))
		s.WriteString("\n\n")
		s.WriteString("Cargando catálogos CISA KEV y base PSIRT...\n")
		s.WriteString("Ejecutando motor de reglas de hardening...\n")
		s.WriteString(DimStyle.Render("\nPor favor espera..."))

	case stateResult:
		if m.scanError != nil {
			s.WriteString(ErrorStyle.Render(fmt.Sprintf("Error crítico durante el escaneo: %v", m.scanError)))
		} else {
			s.WriteString(SubtitleStyle.Render("Resultados de la Auditoría:"))
			s.WriteString("\n\n")
			s.WriteString(m.scanOutput) // Aquí va el texto del reporte generado
		}
		s.WriteString("\n\n")
		s.WriteString(DimStyle.Render("Presiona 'q' para salir."))
	}

	return AppStyle.Render(s.String())
}
