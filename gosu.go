package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
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

var config Config

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
			return LoginResponse{}, errors.New("incorrect password")
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
	return LoginResponse{}, errors.New("user not found")
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
										in := <-connection.In
										if connection.Closed {
											reconnect(connectionId)
										}
										fmt.Fprint(stdin, in)
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

func reconnect(connectionId int) {

}

func closeConnection(connectionId int) error {
	if connectionId >= len(Connections) {
		return errors.New("unknown host id")
	}
	Connections[connectionId].Closed = true
	return nil
}

func sendString(connectionId int, str string) error {
	if connectionId >= len(Connections) {
		return errors.New("unknown host id")
	}
	Connections[connectionId].In <- str
	return nil
}

func sendError(w http.ResponseWriter, e error, s int) {
	http.Error(w, "{\"error\":\""+strings.Replace(e.Error(), "\"", "\\\"", -1)+"\"}", s)
}

type LoginData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func handleLogin(loginData LoginData) (interface{}, error) {
	if response, err := login(loginData.Username, loginData.Password, config); err == nil {
		return response, nil
	} else {
		return nil, err
	}
	return nil, nil
}

func handle(url string, handler func(LoginData) (interface{}, error), data LoginData, w http.ResponseWriter, r *http.Request) bool {
	if r.URL.String() != url {
		return false
	}
	var err error
	var response interface{}
	if err = jsonDecode(r.Body, &data); err == nil {
		response, err = handler(data)
	} else {
		sendError(w, err, 500)
	}
	if data, err := jsonEncode(&response); err == nil {
		w.Write(data)
	} else {
		sendError(w, err, http.StatusInternalServerError)
	}
	return true
}

func main() {
	// Load Config File
	var err error
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
		if handle("/login", handleLogin, LoginData{}, w, r) {
			return
		}
		/*if r.URL.String() == "/login" {
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
		}*/

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
		case "/resize":
			type Resize struct {
				Id   int `json:"id"`
				Cols int `json:"cols"`
				Rows int `json:"rows"`
			}
			var resize Resize
			if err := jsonDecode(r.Body, &resize); err == nil {
				if resize.Id >= len(Connections) {
					sendError(w, errors.New("invalid connection id"), http.StatusInternalServerError)
					return
				}
				connection := Connections[resize.Id]
				size := make([]byte, 16)
				binary.BigEndian.PutUint32(size, uint32(resize.Cols))
				binary.BigEndian.PutUint32(size[4:], uint32(resize.Rows))
				connection.Session.SendRequest("window-change", false, size)
				return
			}
			sendError(w, err, http.StatusInternalServerError)
			return
		case "/read":
			type Read struct {
				Id int `json:"id"`
			}
			var read Read
			if err = jsonDecode(r.Body, &read); err == nil {
				if read.Id >= len(Connections) {
					sendError(w, errors.New("invalid connection id"), http.StatusInternalServerError)
					return
				}
				connection := Connections[read.Id]

				// Sanity Check
				if connection.Closed {
					writeResponse(w, &map[string]interface{}{
						"id":  read.Id,
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
					"id":  read.Id,
					"out": stdout,
					"err": stderr,
				}); err == nil {
					return
				}
			}
			sendError(w, err, http.StatusInternalServerError)
			return
		case "/write":
			type Send struct {
				Id   int    `json:"id"`
				Data string `json:"data"`
			}
			var send Send
			if err := jsonDecode(r.Body, &send); err == nil {
				if err = sendString(send.Id, send.Data); err == nil {
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
			sendError(w, errors.New("unknown uri"), http.StatusNotFound)
			return
		}
	})))
}
