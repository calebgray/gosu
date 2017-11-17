package main

import (
	"log"
	"net/http"
	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"golang.org/x/crypto/ssh"
	"strings"
	"time"
	"encoding/json"
	"io/ioutil"
	"net"
	"io"
	"os"
)

var tokenSecret = []byte("pgpbYOVcEpoAkl0W0leYHeyTs4nbNpZyTgEFZyrJEDwytbUrPfLIjXYhi3X2nkMTg6nWA42qBb6jKe7rzoAwOoxPEVMNyWSw4DPY3JokIDlSbb5MDDo6Y1pU4F4Ryak29iZoPCQVEHuCAKS84uSUsJz2TtLmKf7g02Hu1sRYxpk87QlWLFXowZBw5d0WLvHyygvHId6E")

type Config struct {
	Users []User `json:"users"`
	Hosts []Host `json:"hosts"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Host struct {
	Host      string `json:"host"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	PublicKey string `json:"publicKey"`
}

var DefaultConfig = Config{
	[]User{
		{
			"admin",
			"admin",
		},
	},
	[]Host{},
}

func loadConfig() (Config, error) {
	// Load Config File
	var config Config
	if configFile, err := os.OpenFile("config.json", os.O_RDONLY, 0644); err == nil {
		if err := json.NewDecoder(configFile).Decode(&config); err != nil {
			return DefaultConfig, err
		}
		configFile.Close()
		return config, nil
	}
	return DefaultConfig, nil
}

func saveConfig(config Config) error {
	if raw, err := json.MarshalIndent(config, "", "\t"); err == nil {
		if err := ioutil.WriteFile("config.json", raw, 0644); err != nil {
			return err
		}
	} else {
		return err
	}
	return nil
}

func readPublicKey(raw []byte) (ssh.AuthMethod, error) {
	var err error
	var key ssh.PublicKey
	if key, err = ssh.ParsePublicKey(raw); err == nil {
		var signer ssh.Signer
		if signer, err = ssh.NewSignerFromKey(key); err == nil {
			return ssh.PublicKeys(signer), nil
		}
	}
	return nil, err
}

func main() {
	// Load Config File
	var err error
	var config Config
	if config, err = loadConfig(); err != nil {
		log.Fatal("Error Parsing Config:", err.Error())
		return
	}
	if err = saveConfig(config); err != nil {
		log.Fatal("Error Saving Config:", err.Error())
		return
	}

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

		// Login?
		if r.URL.String() == "/login" {
			var err error
			var login map[string]string
			if err = json.NewDecoder(r.Body).Decode(&login); err == nil {
				for _, user := range config.Users {
					if user.Username == login["username"] && user.Password == login["password"] {
						token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
							Id:        user.Username,
							ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
						}).SignedString(tokenSecret)

						var body []byte
						if body, err = json.Marshal(&token); err == nil {
							w.Write(body)
							return
						}
						break
					}
				}

			}
			http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", http.StatusInternalServerError)
			return
		}

		// Verify Authorization Token
		var claims *jwt.StandardClaims
		if token, err := request.ParseFromRequestWithClaims(r, request.AuthorizationHeaderExtractor, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			return tokenSecret, nil
		}); err != nil || !token.Valid {
			println(token)
			http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", http.StatusUnauthorized)
			return
		} else {
			claims = token.Claims.(*jwt.StandardClaims)
		}

		// Verify User
		var user User
		for _, user = range config.Users {
			if user.Username == claims.Id {
				break
			}
		}

		// Handle the Request
		switch r.URL.String() {
		case "/bootstrap":
			var err error
			var bootstrap map[string]string
			if err = json.NewDecoder(r.Body).Decode(&bootstrap); err == nil {
				var auth []ssh.AuthMethod
				if len(bootstrap["public_key"]) == 0 {
					auth = []ssh.AuthMethod{
						ssh.Password(bootstrap["password"]),
					}
				} else {
					var key ssh.AuthMethod
					if key, err = readPublicKey([]byte(bootstrap["public_key"])); err == nil {
						auth = []ssh.AuthMethod{
							key,
							ssh.Password(bootstrap["password"]),
						}
					} else {
						goto bootstrapError
					}
				}

				var connection *ssh.Client
				if connection, err = ssh.Dial("tcp", bootstrap["host"], &ssh.ClientConfig{
					User: bootstrap["username"],
					Auth: auth,
					HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
						return nil // TODO: Store and check the host key.
					},
				}); err == nil {
					var session *ssh.Session
					if session, err = connection.NewSession(); err == nil {
						defer session.Close()
						var stdout io.Reader
						if stdout, err = session.StdoutPipe(); err == nil {
							if err = session.RequestPty("xterm", 1, 1, ssh.TerminalModes{}); err == nil {
								if err = session.Run("ls -l /"); err == nil {
									// Respond
									var result []byte
									if result, err = ioutil.ReadAll(stdout); err == nil {
										bootstrap = make(map[string]string)
										bootstrap["result"] = string(result)

										var body []byte
										if body, err = json.Marshal(&bootstrap); err == nil {
											w.Write(body)
											return
										}
									}
								}
							}
						}
					}
				}
			}

		bootstrapError:
			http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", http.StatusInternalServerError)
			return
		case "/status":
			// Return Empty Result
			w.Write([]byte("{}"))
			return
		default:
			// Not Found
			http.Error(w, "{\"error\":\"Unknown URI.\"}", http.StatusNotFound)
			return
		}
	})))
}
