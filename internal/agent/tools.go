package agent

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/asii-mov/codesucks-ai/internal/repo"
)

// Tool names shared by both agent roles.
const (
	toolReadFile = "read_file"
	toolListDir  = "list_dir"
	toolSearch   = "search"
)

// readOnlyTools returns the file-exploration tools available to every agent.
func readOnlyTools() []anthropic.ToolUnionParam {
	read := anthropic.ToolParam{
		Name:        toolReadFile,
		Description: anthropic.String("Read a repository file. Optionally restrict to a 1-indexed line range."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"path":       map[string]any{"type": "string", "description": "Repository-relative file path."},
				"start_line": map[string]any{"type": "integer", "description": "Optional 1-indexed first line."},
				"end_line":   map[string]any{"type": "integer", "description": "Optional 1-indexed last line."},
			},
			Required: []string{"path"},
		},
	}
	list := anthropic.ToolParam{
		Name:        toolListDir,
		Description: anthropic.String("List the entries of a repository directory."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"path": map[string]any{"type": "string", "description": "Repository-relative directory (\".\" for root)."},
			},
			Required: []string{"path"},
		},
	}
	search := anthropic.ToolParam{
		Name:        toolSearch,
		Description: anthropic.String("Search repository files for a literal string or regular expression."),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]any{
				"query":       map[string]any{"type": "string", "description": "Text or regex to search for."},
				"is_regex":    map[string]any{"type": "boolean", "description": "Treat query as a regular expression."},
				"path":        map[string]any{"type": "string", "description": "Optional subdirectory to scope the search."},
				"max_results": map[string]any{"type": "integer", "description": "Optional cap on matches (default 100)."},
			},
			Required: []string{"query"},
		},
	}
	return []anthropic.ToolUnionParam{
		{OfTool: &read},
		{OfTool: &list},
		{OfTool: &search},
	}
}

type readFileArgs struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

type listDirArgs struct {
	Path string `json:"path"`
}

type searchArgs struct {
	Query      string `json:"query"`
	IsRegex    bool   `json:"is_regex"`
	Path       string `json:"path"`
	MaxResults int    `json:"max_results"`
}

// dispatchTool executes a read-only tool call against the sandbox and returns
// the result text plus whether it should be reported to the model as an error.
func dispatchTool(fs *repo.Sandbox, name, rawInput string) (string, bool) {
	switch name {
	case toolReadFile:
		var a readFileArgs
		if err := json.Unmarshal([]byte(rawInput), &a); err != nil {
			return "invalid arguments: " + err.Error(), true
		}
		content, err := fs.ReadFile(a.Path, a.StartLine, a.EndLine)
		if err != nil {
			return err.Error(), true
		}
		return content, false

	case toolListDir:
		var a listDirArgs
		if err := json.Unmarshal([]byte(rawInput), &a); err != nil {
			return "invalid arguments: " + err.Error(), true
		}
		entries, err := fs.ListDir(a.Path)
		if err != nil {
			return err.Error(), true
		}
		return strings.Join(entries, "\n"), false

	case toolSearch:
		var a searchArgs
		if err := json.Unmarshal([]byte(rawInput), &a); err != nil {
			return "invalid arguments: " + err.Error(), true
		}
		sub := a.Path
		if sub == "" {
			sub = "."
		}
		matches, err := fs.Search(a.Query, a.IsRegex, sub, a.MaxResults)
		if err != nil {
			return err.Error(), true
		}
		if len(matches) == 0 {
			return "(no matches)", false
		}
		var b strings.Builder
		for _, m := range matches {
			fmt.Fprintf(&b, "%s:%d: %s\n", m.File, m.Line, m.Text)
		}
		return b.String(), false

	default:
		return "unknown tool: " + name, true
	}
}
