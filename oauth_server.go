package tmoauth

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"tmapi/config"
)

var serverUp bool = false
var oauthVerifier chan string
var redirectAddr chan string

//WaitForOauthVerify func
func WaitForOauthVerify() string {
	return <-oauthVerifier
}

func listenAndServe() {
	addr := fmt.Sprintf(":%d", config.Settings.ServerPort)
	log.Println("[Server] Starting Server")
	err := http.ListenAndServeTLS(addr, config.Settings.ServerCertFile, config.Settings.ServerKeyFile, nil)
	if err != nil {
		log.Fatalf("[Server] Server failed to start: %s\n", err.Error())
	}
}

//StartServer func
func StartServer() {
	if serverUp {
		log.Println("Server already up!")
		return
	}

	log.Println("[Server] Starting server...")

	serverUp = true
	oauthVerifier = make(chan string)
	redirectAddr = make(chan string)

	http.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		addr := <-redirectAddr
		w.Header().Set("Cache-Control", "no-store")
		log.Printf("[Server] Redirecting client to %s\n", addr)
		http.Redirect(w, r, addr, http.StatusFound)
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "text/plain")
		keys, ok := r.URL.Query()["oauth_verifier"]

		if !ok || len(keys[0]) < 1 {
			fmt.Fprintf(w, "Missing oauth_verifier paramter!")
			return
		}

		oauthVerifier <- keys[0]
		fmt.Fprintf(w, "Authenticated!")
		log.Println("[Server] Authenticated a User")
	})

	if _, err := os.Stat(config.Settings.ServerCertFile); err != nil {
		log.Fatalln("[Server] Cannot find ServerCertFile")
	}

	if _, err := os.Stat(config.Settings.ServerKeyFile); err != nil {
		log.Fatalln("[Server] Cannot find ServerKeyFile")
	}

	log.Printf("[Server] Using HTTPS Files: <%s>, <%s>", config.Settings.ServerCertFile, config.Settings.ServerKeyFile)
	go listenAndServe()
}
