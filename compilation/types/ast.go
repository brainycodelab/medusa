package types

import (
	"encoding/json"
)

// ContractKind represents the kind of contract represented by an AST node
type ContractKind string

const (
	// ContractKindContract represents a contract node
	ContractKindContract ContractKind = "contract"
	// ContractKindLibrary represents a library node
	ContractKindLibrary ContractKind = "library"
	// ContractKindInterface represents an interface node
	ContractKindInterface ContractKind = "interface"
)

// Node interface represents a generic AST node
type Node interface {
	GetNodeType() string
}

// ContractDefinition is the contract definition node
type ContractDefinition struct {
	NodeType      string       `json:"nodeType"`
	CanonicalName string       `json:"canonicalName,omitempty"`
	ContractKind  ContractKind `json:"contractKind,omitempty"`
}

func (s ContractDefinition) GetNodeType() string {
	return s.NodeType
}

// AST is the abstract syntax tree
type AST struct {
	NodeType string `json:"nodeType"`
	Nodes    []Node `json:"nodes"`
	Src      string `json:"src"`
}

// UnmarshalJSON custom unmarshaller for AST
func (a *AST) UnmarshalJSON(data []byte) error {
	type Alias AST
	aux := &struct {
		Nodes []json.RawMessage `json:"nodes"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	// Check if nodeType is "SourceUnit"
	if aux.NodeType != "SourceUnit" {
		return nil
	}

	for _, nodeData := range aux.Nodes {
		var nodeType struct {
			NodeType string `json:"nodeType"`
		}

		if err := json.Unmarshal(nodeData, &nodeType); err != nil {
			return err
		}

		var node Node
		switch nodeType.NodeType {
		case "ContractDefinition":
			var cdef ContractDefinition
			if err := json.Unmarshal(nodeData, &cdef); err != nil {
				return err
			}
			node = cdef
		// Add cases for other node types as needed
		default:
			continue
		}

		a.Nodes = append(a.Nodes, node)
	}

	return nil
}
