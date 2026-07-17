package gates

// StackKind is the detected project ecosystem.
type StackKind string

const (
	StackGo      StackKind = "go"
	StackNode    StackKind = "node"
	StackPython  StackKind = "python"
	StackUnknown StackKind = "unknown"
)

// Stack is a detected project stack rooted at a directory.
type Stack struct {
	Kind StackKind
	Dir  string
}

// DetectStack identifies the project's ecosystem from marker files. First match
// wins: go.mod, then package.json, then pyproject.toml/requirements.txt.
func DetectStack(dir string) Stack {
	switch {
	case fileExists(joinRepo(dir, "go.mod")):
		return Stack{StackGo, dir}
	case fileExists(joinRepo(dir, "package.json")):
		return Stack{StackNode, dir}
	case fileExists(joinRepo(dir, "pyproject.toml")), fileExists(joinRepo(dir, "requirements.txt")):
		return Stack{StackPython, dir}
	default:
		return Stack{StackUnknown, dir}
	}
}
