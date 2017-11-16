package main

import (
	"log"
	"net/http"
	"golang.org/x/crypto/ssh"
	"strings"
	"time"
	"encoding/json"
	"io/ioutil"
	"net"
)

func PublicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil
	}
	return ssh.PublicKeys(key)
}

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
		case "/bootstrap":
			var bootstrap map[string]string

			decoder := json.NewDecoder(r.Body)
			defer r.Body.Close()
			if err := decoder.Decode(&bootstrap); err != nil {
				http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", 404)
				return
			}

			connection, err := ssh.Dial("tcp", bootstrap["host"], &ssh.ClientConfig{
				User: bootstrap["username"],
				Auth: []ssh.AuthMethod{
					ssh.Password(bootstrap["password"]),
					PublicKeyFile(bootstrap["public_key"]),
				},
				HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
					return nil
				},
			})
			if err != nil {
				http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", 404)
				return
			}

			session, err := connection.NewSession()
			if err != nil {
				http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", 404)
				return
			}
			defer session.Close()
			stdout, _ := session.StdoutPipe()

			modes := ssh.TerminalModes{
				ssh.ECHO:          0,     // disable echoing
				ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
				ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
			}
			if err := session.RequestPty("xterm", 80, 40, modes); err != nil {
				http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", 404)
				return
			}

			if err := session.Run("ls -l /"); err != nil {
				http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", 404)
				return
			}
			result, _ := ioutil.ReadAll(stdout)
			bootstrap["result"] = string(result)

			body, err := json.Marshal(&bootstrap)
			if err != nil {
				http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", 404)
				return
			}

			// Respond
			w.Write(body)
			return
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
