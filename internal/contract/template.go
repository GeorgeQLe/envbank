package contract

import (
	"errors"
	"fmt"
	"strings"
)

type Template struct {
	Nodes      []TemplateNode
	References []string
}

type TemplateNode struct {
	Literal   string
	Reference string
}

// ParseTemplate parses secret placeholders without expanding values. It
// returns literal/reference nodes and logical record names in encounter order.
func ParseTemplate(template string) (Template, error) {
	var parsed Template
	for offset := 0; offset < len(template); {
		start := strings.Index(template[offset:], "${")
		if start < 0 {
			if literal := template[offset:]; literal != "" {
				parsed.Nodes = append(parsed.Nodes, TemplateNode{Literal: literal})
			}
			break
		}
		start += offset
		if literal := template[offset:start]; literal != "" {
			parsed.Nodes = append(parsed.Nodes, TemplateNode{Literal: literal})
		}
		end := strings.IndexByte(template[start+2:], '}')
		if end < 0 {
			return Template{}, errors.New("unterminated placeholder")
		}
		end += start + 2
		body := template[start+2 : end]
		if !strings.HasPrefix(body, "secret:") {
			return Template{}, fmt.Errorf("unsupported placeholder at byte %d", start)
		}
		reference := strings.TrimPrefix(body, "secret:")
		if !namePattern.MatchString(reference) {
			return Template{}, fmt.Errorf("invalid secret reference at byte %d", start)
		}
		parsed.Nodes = append(parsed.Nodes, TemplateNode{Reference: reference})
		parsed.References = append(parsed.References, reference)
		offset = end + 1
	}
	return parsed, nil
}
