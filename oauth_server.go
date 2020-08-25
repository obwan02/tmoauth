package tmoauth

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

type OAuthCallbackServerSettings struct {
	CertFile string
	KeyFile  string
	Port     int
}

type OAuthCallbackServer struct {
	Settings   OAuthCallbackServerSettings
	verifyList map[string]chan string
}

//Register Registers a requestToken that will be verified by the server later
func (server *OAuthCallbackServer) Register(requestToken string) {
	server.verifyList[requestToken] = make(chan string)
}

//WaitForOAuthVerify -
func (server *OAuthCallbackServer) WaitForOAuthVerify(requestToken string) string {
	return <-server.verifyList[requestToken]
}

//StartOAuthServer starts an internal OAuth server.
func StartOAuthServer(settings OAuthCallbackServerSettings) (*OAuthCallbackServer, error) {
	log.Println("[Server] Starting OAuth server...")

	var server = OAuthCallbackServer{Settings: settings}
	server.verifyList = make(map[string]chan string)

	http.HandleFunc("/", server.oauthCallbackURLHandler)

	if _, err := os.Stat(settings.CertFile); err != nil {
		log.Println("[Server] Cannot find ServerCertFile")
		return nil, err
	}

	if _, err := os.Stat(settings.KeyFile); err != nil {
		log.Println("[Server] Cannot find ServerKeyFile")
		return nil, err
	}

	log.Printf("[Server] Using HTTPS Files: <%s>, <%s>", settings.CertFile, settings.KeyFile)
	go listenAndServe(settings)

	return &server, nil
}

func (server *OAuthCallbackServer) oauthCallbackURLHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set("Content-Type", "text/plain")

	verifKeys, ok := r.URL.Query()["oauth_verifier"]
	if !ok || len(verifKeys[0]) < 1 {
		fmt.Fprintf(w, "Missing oauth_verifier paramter!")
		return
	}

	requestTokenKeys, ok := r.URL.Query()["oauth_token"]
	if !ok || len(requestTokenKeys[0]) < 1 {
		fmt.Fprintf(w, "Missing oauth_token paramter!")
		return
	}

	//Shorthand non-blocking channel send
	go func() { server.verifyList[requestTokenKeys[0]] <- verifKeys[0] }()
	fmt.Fprintf(w, "Authenticated!")
	log.Println("[Server] Authenticated a User")
}

func listenAndServe(settings OAuthCallbackServerSettings) {
	addr := fmt.Sprintf(":%d", settings.Port)
	log.Println("[Server] Starting Server Listening")
	err := http.ListenAndServeTLS(addr, settings.CertFile, settings.KeyFile, nil)
	if err != nil {
		log.Printf("[Server] Server failed to start: %s\n", err.Error())
	}
}
