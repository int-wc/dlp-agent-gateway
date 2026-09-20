package webui

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed dist/* dist/assets/*
var assets embed.FS

func Handler() http.Handler {
	dist, err := fs.Sub(assets, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested := strings.TrimPrefix(r.URL.Path, "/console/")
		if requested == "" {
			requested = "index.html"
		}
		if _, err := fs.Stat(dist, path.Clean(requested)); err != nil {
			requested = "index.html"
		}
		if requested == "index.html" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			data, _ := fs.ReadFile(dist, "index.html")
			_, _ = w.Write(data)
			return
		}
		r.URL.Path = "/" + requested
		files.ServeHTTP(w, r)
	})
}
