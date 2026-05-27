package parser

import (
	"bufio"
	"io"
	"regexp"
	"strconv"
	"strings"
)

type FGTConfig struct {
	Hostname      string
	Version       string
	Model         string
	Serial        string
	Build         int
	HasHA         bool
	HasSDWAN      bool
	HasFMG        bool
	HasVPN        bool
	VDOMs         []string
	Root          *ASTNode
	LinesParsed   int
}
// Expresiones regulares fijas precompiladas globalmente para optimización
var (
	versionRegex       = regexp.MustCompile(`(?:v|Version:?\s+)(\d+\.\d+\.\d+)`)
	configVersionRegex = regexp.MustCompile(`config-version=.*?-(v?\d+\.\d+\.\d+)`)
	modelRegex         = regexp.MustCompile(`(?:FortiGate|FortiOS)\s+([^:\s,]+)`)
	serialRegex        = regexp.MustCompile(`(?:Serial-Number:?\s+)([A-Z0-9]+)`)
	buildRegex         = regexp.MustCompile(`(?:build|Build:?\s+)(\d+)`)
)

func ParseConfigFile(r io.Reader, debug bool) (*FGTConfig, error) {
	// Límite máximo de 10MB por línea para evitar abortos inesperados con respaldos masivos
	const maxCapacity = 10 * 1024 * 1024
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 1024*1024), maxCapacity)

	config := &FGTConfig{
		Root: &ASTNode{Type: NodeRoot, Key: "root", Line: 0},
	}

	lineNum := 0

	currentNode := config.Root
	currentVDOM := "root"

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if lineNum <= 25 && strings.HasPrefix(line, "#") {
			if strings.HasPrefix(line, "#config-version=") {
				content := strings.TrimPrefix(line, "#config-version=")
				parts := strings.Split(content, "-")
				if len(parts) > 1 {
					config.Model = parts[0]
					versionPart := parts[1]
					config.Version = strings.TrimPrefix(versionPart, "v")
				}
			}
			if matches := versionRegex.FindStringSubmatch(line); len(matches) > 1 && config.Version == "" {
				config.Version = matches[1]
			}
			if matches := modelRegex.FindStringSubmatch(line); len(matches) > 1 && config.Model == "" {
				config.Model = matches[1]
			}
			if matches := serialRegex.FindStringSubmatch(line); len(matches) > 1 {
				config.Serial = matches[1]
			}
			if matches := buildRegex.FindStringSubmatch(line); len(matches) > 1 {
				b, _ := strconv.Atoi(matches[1])
				config.Build = b
			}
			continue
		}

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		cmd := parts[0]

		switch cmd {
		case "config":
			if len(parts) > 1 {
				key := strings.Join(parts[1:], ".")
				newNode := &ASTNode{Type: NodeConfig, Key: key, Line: lineNum, VDOM: currentVDOM}
				currentNode.AddChild(newNode)
				currentNode = newNode
			}
		case "edit":
			if len(parts) > 1 {
				key := strings.Trim(strings.Join(parts[1:], " "), "\"")
				newNode := &ASTNode{Type: NodeEdit, Key: key, Line: lineNum, VDOM: currentVDOM}
				currentNode.AddChild(newNode)
				currentNode = newNode
				if currentNode.Parent != nil && currentNode.Parent.Key == "vdom" {
					currentVDOM = key
					currentNode.VDOM = key
				}
			}
		case "set":
			if len(parts) >= 3 {
				key := parts[1]
				value := strings.Trim(strings.Join(parts[2:], " "), "\"")
				newNode := &ASTNode{Type: NodeSet, Key: key, Value: value, Line: lineNum, VDOM: currentVDOM}
				currentNode.AddChild(newNode)

				if key == "hostname" && currentNode.Key == "system.global" {
					config.Hostname = value
				}
			}
		case "next":
			if currentNode.Type == NodeEdit && currentNode.Parent != nil {
				if currentNode.Parent.Key == "vdom" {
					currentVDOM = "root"
				}
				currentNode = currentNode.Parent
			}
		case "end":
			for currentNode.Parent != nil {
				if currentNode.Type == NodeConfig {
					currentNode = currentNode.Parent
					break
				}
				currentNode = currentNode.Parent
			}
		}
	}

	config.LinesParsed = lineNum
	// Post-processing to detect features
	if config.Root != nil {
		config.HasHA = len(config.Root.FindAllConfigs("system.ha")) > 0
		config.HasSDWAN = len(config.Root.FindAllConfigs("system.sdwan")) > 0
		config.HasFMG = len(config.Root.FindAllConfigs("system.central-management")) > 0
		config.HasVPN = len(config.Root.FindAllConfigs("vpn.ssl.settings")) > 0 || len(config.Root.FindAllConfigs("vpn.ipsec.phase1-interface")) > 0
		
		vdomNodes := config.Root.FindAllConfigs("vdom")
		for _, v := range vdomNodes {
			for _, e := range v.Children {
				if e.Type == NodeEdit { config.VDOMs = append(config.VDOMs, e.Key) }
			}
		}
	}

	return config, scanner.Err()
}

