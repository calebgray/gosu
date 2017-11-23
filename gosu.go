package main

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"golang.org/x/crypto/ssh"
	"fmt"
	"bufio"
	"sync"
)

type Config struct {
	Secret string `json:"secret"`
	Users  []User `json:"users"`
	Hosts  []Host `json:"hosts"`
}

type User struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Tokens   []string `json:"tokens"`
}

type Host struct {
	Host        string `json:"host"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	PublicKey   string `json:"publicKey"`
	AutoConnect bool   `json:"autoConnect"`
}

var DefaultConfig = Config{
	"pgpbYOVcEpoAkl0W0leYHeyTs4nbNpZyTgEFZyrJEDwytbUrPfLIjXYhi3X2nkMTg6nWA42qBb6jKe7rzoAwOoxPEVMNyWSw4DPY3JokIDlSbb5MDDo6Y1pU4F4Ryak29iZoPCQVEHuCAKS84uSUsJz2TtLmKf7g02Hu1sRYxpk87QlWLFXowZBw5d0WLvHyygvHId6E",
	[]User{
		{
			"admin",
			"admin",
			[]string{},
		},
	},
	[]Host{},
}

type Connection struct {
	Session *ssh.Session
	Stdout  io.Reader
	Stderr  io.Reader
	Stdin   io.WriteCloser
}

var Connections []Connection

// TODO: Decrypt Config File
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

// TODO: Encrypt Config File
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

func writeResponse(w http.ResponseWriter, v interface{}) error {
	if body, err := json.Marshal(v); err == nil {
		w.Write(body)
		return nil
	} else {
		return err
	}
}

func jsonEncode(v interface{}) ([]byte, error) {
	if data, err := json.Marshal(v); err == nil {
		return data, nil
	} else {
		return nil, err
	}
}

func jsonDecode(rc io.ReadCloser, output interface{}) error {
	return json.NewDecoder(rc).Decode(&output)
}

type LoginConnectionResponse struct {
	Id   int   `json:"id"`
	Host *Host `json:"host"`
}

type LoginResponse struct {
	Token       string                    `json:"token"`
	Hosts       []Host                    `json:"hosts"`
	Connections []LoginConnectionResponse `json:"connections"`
}

func login(username string, password string, config Config) (LoginResponse, error) {
	for _, user := range config.Users {
		if user.Username != username {
			continue
		}
		if user.Password != password {
			return LoginResponse{}, fmt.Errorf("incorrect password")
		} else {
			// Generate a Token
			token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
				Id:        user.Username,
				ExpiresAt: time.Now().Add(time.Hour * 24).Unix(),
			}).SignedString([]byte(config.Secret))

			// Form the Response
			loginResponse := LoginResponse{
				token,
				config.Hosts,
				[]LoginConnectionResponse{},
			}

			// AutoConnect to Hosts
			for _, host := range config.Hosts {
				if host.AutoConnect {
					if response, err := connect(host, config, false); err == nil {
						loginResponse.Connections = append(loginResponse.Connections, LoginConnectionResponse{
							response.Id,
							&host,
						})
					}
				}
			}

			// Success!
			return loginResponse, nil
		}
	}
	return LoginResponse{}, fmt.Errorf("user not found")
}

type ConnectResponse struct {
	Id int `json:"id"`
}

func connect(host Host, config Config, save bool) (ConnectResponse, error) {
	var err error
	var auth []ssh.AuthMethod
	if len(host.PublicKey) == 0 {
		auth = []ssh.AuthMethod{
			ssh.Password(host.Password),
		}
	} else {
		var key ssh.AuthMethod
		if key, err = readPublicKey([]byte(host.PublicKey)); err == nil {
			auth = []ssh.AuthMethod{
				key,
				ssh.Password(host.Password),
			}
		} else {
			return ConnectResponse{}, err
		}
	}

	var connection *ssh.Client
	if connection, err = ssh.Dial("tcp", host.Host, &ssh.ClientConfig{
		User: host.Username,
		Auth: auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil // TODO: Store and check the host key.
		},
	}); err == nil {
		var session *ssh.Session
		if session, err = connection.NewSession(); err == nil {
			//defer session.Close()
			if err = session.RequestPty("xterm", 100, 1024, ssh.TerminalModes{}); err == nil {
				stdout, err := session.StdoutPipe()
				if err == nil {
					stderr, err := session.StderrPipe()
					if err == nil {
						stdin, err := session.StdinPipe()
						if err == nil {
							if err = session.Shell(); err == nil {
								// Respond
								if save {
									config.Hosts = append(config.Hosts, Host{
										host.Host,
										host.Username,
										host.Password,
										host.PublicKey,
										host.AutoConnect,
									})
									if err = saveConfig(config); err != nil {
										return ConnectResponse{}, err
									}
								}

								// Keep Alive
								go func() {
									var err error
									for err == nil {
										time.Sleep(time.Second * 10)
										_, _, err = connection.SendRequest("keepalive@calebgray.com", true, nil)
									}
								}()

								// Return the Response
								Connections = append(Connections, Connection{
									session,
									stdout,
									stderr,
									stdin,
								})
								return ConnectResponse{
									len(Connections) - 1,
								}, nil
							}
						}
					}
				}
			}
		}
	}
	return ConnectResponse{}, err
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
			type LoginData struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			var loginData LoginData
			if err := jsonDecode(r.Body, &loginData); err == nil {
				if response, err := login(loginData.Username, loginData.Password, config); err == nil {
					if data, err := jsonEncode(&response); err == nil {
						w.Write(data)
					} else {
						http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", http.StatusInternalServerError)
					}
				} else {
					http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", http.StatusInternalServerError)
				}
			} else {
				http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", http.StatusInternalServerError)
			}
			return
		}

		// Verify Authorization Token
		var claims *jwt.StandardClaims
		if token, err := request.ParseFromRequestWithClaims(r, request.AuthorizationHeaderExtractor, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.Secret), nil
		}); err != nil || !token.Valid {
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
		case "/poll":
			var poll map[string]string
			if err = json.NewDecoder(r.Body).Decode(&poll); err == nil {
				id, _ := strconv.Atoi(poll["id"])
				if id >= len(Connections) {
					http.Error(w, "{\"error\":\"unknown host id\"}", http.StatusInternalServerError)
					return
				}
				connection := Connections[id]

				var wg sync.WaitGroup
				wg.Add(1)

				var output, errors string
				go func() {
					scanner := bufio.NewScanner(connection.Stdout)
					for scanner.Scan() {
						output += scanner.Text() + "\n"
					}
					scanner = bufio.NewScanner(connection.Stderr)
					for scanner.Scan() {
						errors += scanner.Text() + "\n"
					}
					wg.Done()
				}()

				// Timeout
				go func() {
					time.Sleep(time.Second * 1)
					wg.Done()
				}()

				// Wait for Output or Timeout
				wg.Wait()

				// Respond
				if err = writeResponse(w, &map[string]interface{}{
					"out": output,
					"err": errors,
				}); err == nil {
					return
				}
			}
			http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", http.StatusInternalServerError)
			return
		case "/execute":
			var execute map[string]string
			if err = json.NewDecoder(r.Body).Decode(&execute); err == nil {
				id, _ := strconv.Atoi(execute["id"])
				if id >= len(Connections) {
					http.Error(w, "{\"error\":\"unknown host id\"}", http.StatusInternalServerError)
					return
				}
				connection := Connections[id]

				fmt.Fprint(connection.Stdin, execute["command"]+"\n")

				// Respond
				var output []byte
				if _, err = connection.Stdout.Read(output); err == nil {
					if err = writeResponse(w, &map[string]interface{}{
						"success": true,
					}); err == nil {
						return
					}
				}
			}
			http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", http.StatusInternalServerError)
			return
		case "/addhost":
			var host Host
			if err := jsonDecode(r.Body, &host); err == nil {
				if response, err := connect(host, config, true); err == nil {
					writeResponse(w, response)
				} else {
					http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", http.StatusInternalServerError)
				}
			} else {
				http.Error(w, "{\"error\":\""+strings.Replace(err.Error(), "\"", "\\\"", -1)+"\"}", http.StatusInternalServerError)
			}
			return
		case "/status":
			// Return Empty Result
			w.Write([]byte("{}"))
			return
		default:
			// Not Found
			http.Error(w, "{\"error\":\"unknown uri\"}", http.StatusNotFound)
			return
		}
	})))
}
