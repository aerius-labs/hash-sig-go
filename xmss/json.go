package xmss

import (
	"encoding/base64"
	"encoding/json"

	"github.com/aerius-labs/hash-sig-go/merkle"
	"github.com/aerius-labs/hash-sig-go/th"
)

// secretKeyJSON is used for JSON serialization
type secretKeyJSON struct {
	PRFKey          string         `json:"PRFKey"`
	Tree            hashTreeJSON   `json:"Tree"`
	Parameter       string         `json:"Parameter"`
	ActivationEpoch int            `json:"ActivationEpoch"`
	NumActiveEpochs int            `json:"NumActiveEpochs"`
}

// hashTreeJSON represents the JSON structure of a HashTree
type hashTreeJSON struct {
	Depth  int                  `json:"depth"`
	Layers []hashTreeLayerJSON  `json:"layers"`
}

// hashTreeLayerJSON represents the JSON structure of a HashTreeLayer
type hashTreeLayerJSON struct {
	StartIndex int      `json:"start_index"`
	Nodes      []string `json:"nodes"`
}

// MarshalJSON implements custom JSON marshaling for SecretKey
func (sk *SecretKey) MarshalJSON() ([]byte, error) {
	// Marshal PRFKey
	prfKeyStr := base64.StdEncoding.EncodeToString(sk.PRFKey)
	
	// Marshal Parameter
	paramStr := base64.StdEncoding.EncodeToString(sk.Parameter)
	
	// Marshal the tree
	treeJSON := hashTreeJSON{
		Depth:  sk.Tree.GetDepth(),
		Layers: make([]hashTreeLayerJSON, 0),
	}
	
	// Get layers from tree
	layers := sk.Tree.GetLayers()
	for _, layer := range layers {
		layerJSON := hashTreeLayerJSON{
			StartIndex: layer.GetStartIndex(),
			Nodes:      make([]string, 0),
		}
		
		// Encode each node
		nodes := layer.GetNodes()
		for _, node := range nodes {
			nodeStr := base64.StdEncoding.EncodeToString(node)
			layerJSON.Nodes = append(layerJSON.Nodes, nodeStr)
		}
		
		treeJSON.Layers = append(treeJSON.Layers, layerJSON)
	}
	
	// Create the JSON structure
	jsonSK := secretKeyJSON{
		PRFKey:          prfKeyStr,
		Tree:            treeJSON,
		Parameter:       paramStr,
		ActivationEpoch: sk.ActivationEpoch,
		NumActiveEpochs: sk.NumActiveEpochs,
	}
	
	return json.Marshal(jsonSK)
}

// UnmarshalJSON implements custom JSON unmarshaling for SecretKey
func (sk *SecretKey) UnmarshalJSON(data []byte) error {
	var jsonSK secretKeyJSON
	if err := json.Unmarshal(data, &jsonSK); err != nil {
		return err
	}
	
	// Unmarshal PRFKey
	prfKey, err := base64.StdEncoding.DecodeString(jsonSK.PRFKey)
	if err != nil {
		return err
	}
	sk.PRFKey = prfKey
	
	// Unmarshal Parameter
	param, err := base64.StdEncoding.DecodeString(jsonSK.Parameter)
	if err != nil {
		return err
	}
	sk.Parameter = param
	
	// Unmarshal the tree
	layers := make([]merkle.HashTreeLayer, 0)
	for _, layerJSON := range jsonSK.Tree.Layers {
		// Decode nodes
		nodes := make([]th.Domain, 0)
		for _, nodeStr := range layerJSON.Nodes {
			node, err := base64.StdEncoding.DecodeString(nodeStr)
			if err != nil {
				return err
			}
			nodes = append(nodes, th.Domain(node))
		}
		
		layer := merkle.NewHashTreeLayer(layerJSON.StartIndex, nodes)
		layers = append(layers, layer)
	}
	
	// Note: We cannot fully reconstruct the tree without knowing which TweakableHash to use
	// This is a limitation compared to Rust which maintains the type parameter
	// The caller must provide the correct TweakableHash instance
	sk.Tree = nil // Will be set by UnmarshalWithTH
	
	sk.ActivationEpoch = jsonSK.ActivationEpoch
	sk.NumActiveEpochs = jsonSK.NumActiveEpochs
	
	return nil
}

// UnmarshalSecretKey unmarshals a SecretKey with the correct TweakableHash
func UnmarshalSecretKey(data []byte, thash th.TweakableHash) (*SecretKey, error) {
	var jsonSK secretKeyJSON
	if err := json.Unmarshal(data, &jsonSK); err != nil {
		return nil, err
	}
	
	// Unmarshal PRFKey
	prfKey, err := base64.StdEncoding.DecodeString(jsonSK.PRFKey)
	if err != nil {
		return nil, err
	}
	
	// Unmarshal Parameter
	param, err := base64.StdEncoding.DecodeString(jsonSK.Parameter)
	if err != nil {
		return nil, err
	}
	
	// Unmarshal the tree layers
	layers := make([]merkle.HashTreeLayer, 0)
	for _, layerJSON := range jsonSK.Tree.Layers {
		// Decode nodes
		nodes := make([]th.Domain, 0)
		for _, nodeStr := range layerJSON.Nodes {
			node, err := base64.StdEncoding.DecodeString(nodeStr)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, th.Domain(node))
		}
		
		layer := merkle.NewHashTreeLayer(layerJSON.StartIndex, nodes)
		layers = append(layers, layer)
	}
	
	// Reconstruct the tree WITH the TweakableHash
	tree := merkle.NewHashTreeFromLayers(jsonSK.Tree.Depth, layers, param, thash)
	
	return &SecretKey{
		PRFKey:          prfKey,
		Tree:            tree,
		Parameter:       param,
		ActivationEpoch: jsonSK.ActivationEpoch,
		NumActiveEpochs: jsonSK.NumActiveEpochs,
	}, nil
}