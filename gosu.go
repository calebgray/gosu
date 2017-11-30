package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	Listen string `json:"listen"`
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
	AutoPoll    bool   `json:"autoPoll"`
}

var randSecret = make([]byte, 1024)
var _, _ = rand.Read(randSecret)

var DefaultConfig = Config{
	":8080",
	base64.StdEncoding.EncodeToString(randSecret),
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
	Client  *ssh.Client
	Session *ssh.Session

	In  chan string
	Out chan string
	Err chan string

	Closed bool
}

var Connections []Connection

// TODO: Decrypt Config File
func loadConfig() (Config, error) {
	// Load Config File
	var config Config
	if configFile, err := os.OpenFile("config.json", os.O_RDONLY, 0644); err == nil {
		defer configFile.Close()
		if err := jsonDecode(configFile, &config); err == nil {
			return config, nil
		}
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
	Id   int  `json:"id"`
	Host Host `json:"host"`
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

	var client *ssh.Client
	if client, err = ssh.Dial("tcp", host.Host, &ssh.ClientConfig{
		User: host.Username,
		Auth: auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil // TODO: Store and check the host key.
		},
	}); err == nil {
		//defer connection.Close()
		var session *ssh.Session
		if session, err = client.NewSession(); err == nil {
			//defer session.Close()
			if err = session.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err == nil {
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
										host.AutoPoll,
									})
									if err = saveConfig(config); err != nil {
										return ConnectResponse{}, err
									}
								}

								// Create Connection
								connectionId := len(Connections)
								connection := Connection{
									client,
									session,

									make(chan string),
									make(chan string),
									make(chan string),

									false,
								}

								// IO Channels
								go func() {
									for {
										fmt.Fprint(stdin, <-connection.In)
									}
									log.Print("Connection (", connectionId, ") stdin failed.")
									closeConnection(connectionId)
								}()
								pipeToChannel := func(r io.Reader, c chan string) {
									var n int
									bytes := make([]byte, 1024)
									for {
										if n, err = r.Read(bytes); err == nil {
											c <- string(bytes[:n])
										} else {
											break
										}
									}
									log.Print("Connection (", connectionId, ") failed: ", err.Error())
									closeConnection(connectionId)
								}
								go pipeToChannel(stdout, connection.Out)
								go pipeToChannel(stderr, connection.Err)

								// Return the Response
								Connections = append(Connections, connection)
								return ConnectResponse{
									connectionId,
									host,
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

func closeConnection(connectionId int) error {
	if connectionId >= len(Connections) {
		return fmt.Errorf("unknown host id")
	}
	Connections[connectionId].Closed = true
	return nil
}

func sendInput(connectionId int, command string) error {
	if connectionId >= len(Connections) {
		return fmt.Errorf("unknown host id")
	}
	Connections[connectionId].In <- command
	return nil
}

func sendError(w http.ResponseWriter, e error, s int) {
	http.Error(w, "{\"error\":\""+strings.Replace(e.Error(), "\"", "\\\"", -1)+"\"}", s)
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
	log.Println("Listening on", config.Listen)
	log.Fatal(http.ListenAndServe(config.Listen, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
						sendError(w, err, http.StatusInternalServerError)
					}
				} else {
					sendError(w, err, http.StatusInternalServerError)
				}
			} else {
				sendError(w, err, http.StatusInternalServerError)
			}
			return
		}

		// Verify Authorization Token
		var claims *jwt.StandardClaims
		if token, err := request.ParseFromRequestWithClaims(r, request.AuthorizationHeaderExtractor, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte(config.Secret), nil
		}); err != nil || !token.Valid {
			sendError(w, err, http.StatusUnauthorized)
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
			type Poll struct {
				Id int `json:"id"`
			}
			var poll Poll
			if err = jsonDecode(r.Body, &poll); err == nil {
				if poll.Id >= len(Connections) {
					sendError(w, err, http.StatusInternalServerError)
					return
				}
				connection := Connections[poll.Id]

				// Sanity Check
				if connection.Closed {
					writeResponse(w, &map[string]interface{}{
						"id":  poll.Id,
						"out": nil,
						"err": nil,
					})
					return
				}

				// Read Channels
				var stdout, stderr string
				for len(stdout) == 0 && len(stderr) == 0 {
					if connection.Out != nil {
						select {
						case stdout = <-connection.Out:
						default:
						}
					}
					if connection.Err != nil {
						select {
						case stderr = <-connection.Err:
						default:
						}
					}
				}

				// Respond
				if err = writeResponse(w, &map[string]interface{}{
					"id":  poll.Id,
					"out": stdout,
					"err": stderr,
				}); err == nil {
					return
				}
			}
			sendError(w, err, http.StatusInternalServerError)
			return
		case "/execute":
			type Execute struct {
				Id      int    `json:"id"`
				Command string `json:"command"`
			}
			var execute Execute
			if err := jsonDecode(r.Body, &execute); err == nil {
				if err = sendInput(execute.Id, execute.Command+"\n"); err == nil {
					if err = writeResponse(w, &map[string]interface{}{
						"success": true,
					}); err == nil {
						return
					}
				}
			}
			sendError(w, err, http.StatusInternalServerError)
			return
		case "/addhost":
			var host Host
			if err := jsonDecode(r.Body, &host); err == nil {
				if response, err := connect(host, config, true); err == nil {
					writeResponse(w, response)
				} else {
					sendError(w, err, http.StatusInternalServerError)
				}
			} else {
				sendError(w, err, http.StatusInternalServerError)
			}
			return
		case "/status":
			// Return Empty Result
			w.Write([]byte("{}"))
			return
		default:
			// Not Found
			sendError(w, fmt.Errorf("unknown uri"), http.StatusNotFound)
			return
		}
	})))
}
