package main

import (
	"log"
	"net/http"
	"strings"
	"time"
)

func handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.URL.String())
		if strings.Contains(r.Header.Get("Accept"), "application/json") {
			// Set the Content Type
			w.Header().Set("Content-Type", "application/json")

			// Disable Browser Caching
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "Thu, 28 May 1987 04:00:00 GMT")

			time.Sleep(time.Second)
			w.Write([]byte("{}"))
		} else {
			h.ServeHTTP(w, r)
		}
	})
}

func main() {
	err := http.ListenAndServe(":8080", handler(http.FileServer(http.Dir("public"))))
	log.Fatal(err)
}
