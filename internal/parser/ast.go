package parser

import (
	"strings"
)

type NodeType int

const (
	NodeRoot NodeType = iota
	NodeConfig
	NodeEdit
	NodeSet
)

type FirewallPolicy struct {
	ID       string
	Name     string
	VDOM     string
	Line     int
	SrcIntf  []string
	DstIntf  []string
	SrcAddr  []string
	DstAddr  []string
	Service  []string
	Action   string
	Status   string
	Logging  string
	Schedule string
}

type LocalInPolicy struct {
	ID      string
	Intf    string
	SrcAddr []string
	DstAddr []string
	Service []string
	Action  string
	Status  string
	VDOM    string
	Line    int
}

type ServiceCustom struct {
	Name     string
	Protocol string // TCP/UDP/SCTP
	Port     string // dst-port range
	VDOM     string
	Line     int
}

type NetworkObject struct {
	Name  string
	Type  string // address, service, addrgrp
	Value string
	VDOM  string
	Line  int
}

func (n *ASTNode) ExtractLocalInPolicies() []LocalInPolicy {
	var policies []LocalInPolicy
	configNodes := n.FindAllConfigs("system.local-in-policy")
	for _, configNode := range configNodes {
		for _, editNode := range configNode.Children {
			if editNode.Type == NodeEdit {
				p := LocalInPolicy{
					ID:     editNode.Key,
					Status: "enable",
					VDOM:   editNode.VDOM,
					Line:   editNode.Line,
				}
				for _, setNode := range editNode.Children {
					if setNode.Type == NodeSet {
						val := strings.Trim(setNode.Value, "\"")
						tokens := strings.Fields(val)
						switch setNode.Key {
						case "intf":    p.Intf = val
						case "srcaddr": p.SrcAddr = tokens
						case "dstaddr": p.DstAddr = tokens
						case "service": p.Service = tokens
						case "action":  p.Action = val
						case "status":  p.Status = val
						}
					}
				}
				policies = append(policies, p)
			}
		}
	}
	return policies
}

func (n *ASTNode) ExtractServiceCustoms() []ServiceCustom {
	var svcs []ServiceCustom
	configNodes := n.FindAllConfigs("firewall.service.custom")
	for _, configNode := range configNodes {
		for _, editNode := range configNode.Children {
			if editNode.Type == NodeEdit {
				s := ServiceCustom{Name: editNode.Key, VDOM: editNode.VDOM, Line: editNode.Line}
				for _, setNode := range editNode.Children {
					if setNode.Type == NodeSet {
						val := strings.Trim(setNode.Value, "\"")
						switch setNode.Key {
						case "tcp-portrange":
							s.Protocol = "TCP"
							s.Port = val
						case "udp-portrange":
							s.Protocol = "UDP"
							s.Port = val
						}
					}
				}
				svcs = append(svcs, s)
			}
		}
	}
	return svcs
}

func (n *ASTNode) ExtractPolicies() []FirewallPolicy {
	var policies []FirewallPolicy
	configNodes := n.FindAllConfigs("firewall.policy")
	for _, configNode := range configNodes {
		for _, policyNode := range configNode.Children {
			if policyNode.Type == NodeEdit {
				p := FirewallPolicy{
					ID:    policyNode.Key,
					Status: "enable",
					VDOM:  policyNode.VDOM,
					Line:  policyNode.Line,
				}

				for _, setNode := range policyNode.Children {
					if setNode.Type == NodeSet {
						val := strings.Trim(setNode.Value, "\"")
						tokens := strings.Fields(val)
						switch setNode.Key {
						case "name": p.Name = val
						case "srcintf": p.SrcIntf = tokens
						case "dstintf": p.DstIntf = tokens
						case "srcaddr": p.SrcAddr = tokens
						case "dstaddr": p.DstAddr = tokens
						case "service": p.Service = tokens
						case "action": p.Action = val
						case "status": p.Status = val
						case "logtraffic": p.Logging = val
						}
					}
				}
				policies = append(policies, p)
			}
		}
	}
	return policies
}

func (n *ASTNode) ExtractObjects() []NetworkObject {
	var objects []NetworkObject
	
	addrNodes := n.FindAllConfigs("firewall.address")
	for _, configNode := range addrNodes {
		for _, editNode := range configNode.Children {
			if editNode.Type == NodeEdit {
				obj := NetworkObject{Type: "address", Name: editNode.Key, Line: editNode.Line, VDOM: editNode.VDOM}
				for _, setNode := range editNode.Children {
					if setNode.Key == "subnet" || setNode.Key == "fqdn" {
						obj.Value = setNode.Value
					}
				}
				objects = append(objects, obj)
			}
		}
	}

	svcNodes := n.FindAllConfigs("firewall.service.custom")
	for _, configNode := range svcNodes {
		for _, editNode := range configNode.Children {
			if editNode.Type == NodeEdit {
				objects = append(objects, NetworkObject{Type: "service", Name: editNode.Key, Line: editNode.Line, VDOM: editNode.VDOM})
			}
		}
	}

	return objects
}

// SEC-FIX A-01: Límite de profundidad para prevenir stack overflow con archivos .conf maliciosos
const maxASTDepth = 50

func (n *ASTNode) FindAllConfigs(key string) []*ASTNode {
	return n.findAllConfigsDepth(key, 0)
}

func (n *ASTNode) findAllConfigsDepth(key string, depth int) []*ASTNode {
	if depth > maxASTDepth {
		return nil
	}
	var results []*ASTNode
	if n.Type == NodeConfig && n.Key == key {
		results = append(results, n)
	}
	for _, child := range n.Children {
		results = append(results, child.findAllConfigsDepth(key, depth+1)...)
	}
	return results
}

type ASTNode struct {
	Type     NodeType
	Key      string
	Value    string
	VDOM     string
	Line     int
	Parent   *ASTNode
	Children []*ASTNode
}

func (n *ASTNode) AddChild(child *ASTNode) {
	child.Parent = n
	n.Children = append(n.Children, child)
}

func (n *ASTNode) FindPath(path string) []*ASTNode {
	parts := strings.Split(path, ".")
	return n.findRecursive(parts, 0)
}

// SEC-FIX A-01: Recursión con límite de profundidad
func (n *ASTNode) findRecursive(parts []string, depth int) []*ASTNode {
	if len(parts) == 0 {
		return []*ASTNode{n}
	}
	if depth > maxASTDepth {
		return nil
	}

	var results []*ASTNode
	target := parts[0]

	for _, child := range n.Children {
		if target == "*" || child.Key == target {
			results = append(results, child.findRecursive(parts[1:], depth+1)...)
		} else {
			if strings.HasPrefix(child.Key, target+".") || strings.HasSuffix(child.Key, "."+target) || strings.Contains(child.Key, "."+target+".") {
				if strings.HasPrefix(child.Key, target) {
					nodeParts := strings.Split(child.Key, ".")
					matchLen := 0
					for i := 0; i < len(nodeParts) && i < len(parts); i++ {
						if nodeParts[i] == parts[i] { matchLen++ } else { break }
					}
					if matchLen > 0 {
						results = append(results, child.findRecursive(parts[matchLen:], depth+1)...)
					}
				}
			}
		}
	}
	return results
}

func (n *ASTNode) GetPath() string {
	var parts []string
	curr := n
	for curr != nil && curr.Type != NodeRoot {
		parts = append([]string{curr.Key}, parts...)
		curr = curr.Parent
	}
	return strings.Join(parts, ".")
}
