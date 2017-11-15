package main

import (
	"log"
	"net/http"
	"strings"
	"time"
)

func main() {
	// Fallback to File Server
	fileServer := http.FileServer(http.Dir("public"))
	log.Fatal(http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log Requests
		log.Println(r.URL.String())

		// Serve a Static File?
		if !strings.Contains(r.Header.Get("Accept"), "application/json") {
			fileServer.ServeHTTP(w, r)
			return
		}

		// Disable Browser Caching
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "Thu, 28 May 1987 04:00:00 GMT")

		// Set the Content Type
		w.Header().Set("Content-Type", "application/json")

		// Handle the Request
		switch r.URL.String() {
		case "/status":
			// Return Empty Result
			w.Write([]byte("{}"))
			return
		case "/login":
			// Simulate Logic
			time.Sleep(time.Second)
			// Return Empty Result
			w.Write([]byte("{}"))
			return
		default:
			// Not Found
			http.Error(w, "{\"error\":\"Unknown URI.\"}", 404)
			return
		}
	})))
}
