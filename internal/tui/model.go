package tui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type state int

const (
	stateFilePicker state = iota
	stateManualPath
	stateOptions
	stateReportName
	stateScanning
	stateResult
)

type scanFinishedMsg struct {
	results string
}

type scanErrorMsg struct {
	err error
}

type Model struct {
	state        state
	filepicker   filepicker.Model
	textInput    textinput.Model
	pathInput    textinput.Model
	selectedFile string
	cursorOption int
	liveEnabled  bool
	reportName   string
	scanOutput   string
	scanError    error
	quitting     bool

	runAuditFunc func(path string, liveEnabled bool, reportName string) (string, error)
}

func InitialModel(auditFunc func(string, bool, string) (string, error)) Model {
	fp := filepicker.New()
	fp.AllowedTypes = []string{".conf"}
	fp.CurrentDirectory, _ = os.Getwd()
	fp.Height = 10
	fp.ShowHidden = true // Permite ver ".." para subir de directorio
	fp.AutoHeight = false

	ti := textinput.New()
	ti.Placeholder = "reporte_tricera (sin extensión)"
	ti.Focus()
	ti.CharLimit = 156
	ti.Width = 30

	pi := textinput.New()
	pi.Placeholder = "C:\\rutas\\absolutas\\hasta\\archivo.conf"
	pi.Focus()
	pi.CharLimit = 255
	pi.Width = 50

	return Model{
		state:        stateFilePicker,
		filepicker:   fp,
		textInput:    ti,
		pathInput:    pi,
		runAuditFunc: auditFunc,
	}
}

func (m Model) Init() tea.Cmd {
	return m.filepicker.Init()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			m.quitting = true
			return m, tea.Quit
		case "esc":
			if m.state == stateOptions {
				m.state = stateFilePicker
				return m, nil
			} else if m.state == stateReportName {
				m.state = stateOptions
				return m, nil
			} else if m.state == stateManualPath {
				m.state = stateFilePicker
				m.scanError = nil
				return m, nil
			}
		case "p":
			if m.state == stateFilePicker {
				m.state = stateManualPath
				m.scanError = nil
				return m, textinput.Blink
			}
		case "up", "k":
			if m.state == stateOptions {
				m.cursorOption--
				if m.cursorOption < 0 {
					m.cursorOption = 1
				}
			}
		case "down", "j":
			if m.state == stateOptions {
				m.cursorOption++
				if m.cursorOption > 1 {
					m.cursorOption = 0
				}
			}
		case "enter":
			if m.state == stateOptions {
				if m.cursorOption == 0 {
					m.liveEnabled = false
				} else {
					m.liveEnabled = true
				}
				m.state = stateReportName
				return m, textinput.Blink
			} else if m.state == stateReportName {
				m.reportName = strings.TrimSpace(m.textInput.Value())
				if m.reportName == "" {
					m.reportName = "reporte_tricera.html"
				} else {
					// Asegurar que tenga extensión html
					if !strings.HasSuffix(strings.ToLower(m.reportName), ".html") {
						m.reportName += ".html"
					}
				}
				m.state = stateScanning
				return m, m.startScanCmd(m.selectedFile)
			} else if m.state == stateManualPath {
				path := m.pathInput.Value()
				if path != "" {
					info, err := os.Stat(path)
					if err == nil && !info.IsDir() {
						m.selectedFile = path
						m.state = stateOptions
						m.scanError = nil
						return m, nil
					} else {
						m.scanError = fmt.Errorf("El archivo no existe o es un directorio.")
					}
				}
			}
		}

	case scanFinishedMsg:
		m.state = stateResult
		m.scanOutput = msg.results
		return m, nil

	case scanErrorMsg:
		m.state = stateResult
		m.scanError = msg.err
		return m, nil
	}

	var cmd tea.Cmd
	switch m.state {
	case stateFilePicker:
		var fpCmd tea.Cmd
		m.filepicker, fpCmd = m.filepicker.Update(msg)

		if didSelect, path := m.filepicker.DidSelectFile(msg); didSelect {
			m.selectedFile = path
			m.state = stateOptions
			return m, fpCmd
		}

		if didSelect, path := m.filepicker.DidSelectDisabledFile(msg); didSelect {
			m.scanError = fmt.Errorf("archivo no permitido: %s", path)
		}

		cmd = fpCmd
		
	case stateReportName:
		var tiCmd tea.Cmd
		m.textInput, tiCmd = m.textInput.Update(msg)
		cmd = tiCmd
		
	case stateManualPath:
		var piCmd tea.Cmd
		m.pathInput, piCmd = m.pathInput.Update(msg)
		cmd = piCmd
	}

	return m, cmd
}

func (m Model) startScanCmd(path string) tea.Cmd {
	return func() tea.Msg {
		// Breve pausa para apreciación visual del loader
		time.Sleep(500 * time.Millisecond)
		if m.runAuditFunc != nil {
			out, err := m.runAuditFunc(path, m.liveEnabled, m.reportName)
			if err != nil {
				return scanErrorMsg{err}
			}
			return scanFinishedMsg{out}
		}
		return scanErrorMsg{fmt.Errorf("motor de auditoría no conectado")}
	}
}

func StartApp(auditFunc func(string, bool, string) (string, error)) error {
	p := tea.NewProgram(InitialModel(auditFunc), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
