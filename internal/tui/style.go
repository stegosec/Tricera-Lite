package tui

import "github.com/charmbracelet/lipgloss"

var (
	// Paleta de colores Hacker
	cyan  = lipgloss.Color("#00FFFF")
	green = lipgloss.Color("#00FF00")
	red   = lipgloss.Color("#FF0000")
	gray  = lipgloss.Color("#555555")

	// Estilos Base
	AppStyle = lipgloss.NewStyle().Padding(1, 2)

	TitleStyle = lipgloss.NewStyle().
		Foreground(cyan).
		Bold(true).
		Border(lipgloss.DoubleBorder(), true).
		BorderForeground(cyan).
		Padding(0, 1)

	SubtitleStyle = lipgloss.NewStyle().
		Foreground(green).
		Bold(true)

	ErrorStyle = lipgloss.NewStyle().
		Foreground(red).
		Bold(true)

	HighlightStyle = lipgloss.NewStyle().
		Foreground(cyan)

	DimStyle = lipgloss.NewStyle().
		Foreground(gray)
)
