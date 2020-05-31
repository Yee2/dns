package main

import (
	"strings"
)

func Compare(parent, child string) bool {
	j1 := len(parent)
	j2 := len(child)
	if parent[j1-1] == '.' {
		j1 -= 1
	}
	if child[j2-1] == '.' {
		j2 -= 1
	}

	for {
		i1 := prevLabel(parent[:j1])
		i2 := prevLabel(child[:j2])

		if i1 == 0 && parent[i1:j1] == "**" && child[i2:j2] != "" {
			return true
		}

		if !equal(parent[i1:j1], child[i2:j2]) {
			return false
		}

		if i1 == 0 && i2 == 0 {
			return true
		}
		if i1 == 0 || i2 == 0 {
			return false
		}

		j1 = i1 - 1
		j2 = i2 - 1

	}

}
func prevLabel(s string) int {
	for i := len(s); i > 0; i-- {
		if s[i-1] == '.' {
			return i
		}
	}
	return 0
}

func equal(parent, child string) bool {
	if len(parent) == 0 || len(child) == 0 {
		return false
	}
	return parent == "*" || strings.ToLower(parent) == strings.ToLower(child)
}
