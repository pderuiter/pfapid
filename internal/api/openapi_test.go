package api

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// TestOpenAPICoversRoutes keeps api/openapi.yaml and the router in step:
// every route has a spec operation and every spec operation a route.
func TestOpenAPICoversRoutes(t *testing.T) {
	spec, err := os.ReadFile("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	var routes []string
	for _, m := range regexp.MustCompile(`(?:route|check)\("([A-Z]+) (/v1/[^"]+)"`).FindAllStringSubmatch(string(src), -1) {
		routes = append(routes, strings.ToLower(m[1])+" "+m[2])
	}
	var ops []string
	path := ""
	for _, line := range strings.Split(string(spec), "\n") {
		if m := regexp.MustCompile(`^  (/v1/\S+):$`).FindStringSubmatch(line); m != nil {
			path = m[1]
			continue
		}
		if m := regexp.MustCompile(`^    (get|put|post|delete):$`).FindStringSubmatch(line); m != nil && path != "" {
			ops = append(ops, m[1]+" "+path)
		}
		if strings.HasPrefix(line, "components:") {
			break
		}
	}
	sort.Strings(routes)
	sort.Strings(ops)
	if len(routes) == 0 || strings.Join(routes, "\n") != strings.Join(ops, "\n") {
		t.Fatalf("router and openapi.yaml differ\nrouter:\n%s\nspec:\n%s", strings.Join(routes, "\n"), strings.Join(ops, "\n"))
	}
}
