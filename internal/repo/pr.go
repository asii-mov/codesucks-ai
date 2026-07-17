package repo

import (
	"context"
	"fmt"

	"github.com/google/go-github/v66/github"
)

// PRInput describes a pull request to open.
type PRInput struct {
	Owner string
	Repo  string
	Head  string // fix branch
	Base  string // target/default branch
	Title string
	Body  string
}

// CreatePR opens a pull request and returns its number and HTML URL.
func CreatePR(ctx context.Context, token string, in PRInput) (number int, htmlURL string, err error) {
	client := github.NewClient(nil).WithAuthToken(token)
	pr, _, err := client.PullRequests.Create(ctx, in.Owner, in.Repo, &github.NewPullRequest{
		Title: github.String(in.Title),
		Head:  github.String(in.Head),
		Base:  github.String(in.Base),
		Body:  github.String(in.Body),
	})
	if err != nil {
		return 0, "", fmt.Errorf("create PR: %w", err)
	}
	return pr.GetNumber(), pr.GetHTMLURL(), nil
}
