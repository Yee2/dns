package main

var config = struct {
	Servers []struct {
		Type    string `toml:"type"`
		Address string `toml:"address"`
	} `toml:"listen"`
	Upstreams []struct {
		Name    string `toml:"name"`
		Method  string `toml:"method"`
		Address string `toml:"address"`
	} `toml:"upstreams"`
	Rules []struct {
		Name     string `toml:"name"`
		Action   string `toml:"action"`
		Answer   string `toml:"answer"`
		Upstream string `toml:"upstream"`
	} `toml:"rules"`
	Groups map[string]struct {
		Name string   `toml:"name"`
		List []string `toml:"list"`
	} `toml:"groups"`
}{}
