package tmoauth

import (
	"errors"
	"fmt"
	"log"
	"net/url"

	"github.com/dghubble/oauth1"
)

//SessionSettings holds all the settings for an individual session
type SessionSettings struct {
	ConsumerKey    string
	ConsumerSecret string
	CallbackServer *OAuthCallbackServer
	Sandbox        bool
}

//TMSession struct
type TMSession struct {
	Config *oauth1.Config

	//Used Internally
	requestToken   *oauth1.Token
	accessToken    *oauth1.Token
	callbackServer *OAuthCallbackServer
}

//MakeNewTMSession func
func MakeNewTMSession(sessSettings *SessionSettings) *TMSession {

	session := TMSession{callbackServer: sessSettings.CallbackServer}
	session.Config = oauth1.NewConfig(sessSettings.ConsumerKey, sessSettings.ConsumerSecret)
	//Cbf righting a proper mechanism here to get the callback url
	//Probs gonna bite me in the ass if I try to make the server remote but oh well
	session.Config.CallbackURL = fmt.Sprintf("https://localhost:%d", session.callbackServer.Settings.Port)

	host := "trademe"
	if sessSettings.Sandbox {
		host = "tmsandbox"
	}

	session.Config.Endpoint = oauth1.Endpoint{
		RequestTokenURL: fmt.Sprintf("https://secure.%s.co.nz/RequestToken", host),
		AuthorizeURL:    fmt.Sprintf("https://secure.%s.co.nz/Authorize", host),
		AccessTokenURL:  fmt.Sprintf("https://secure.%s.co.nz/AccessToken", host),
	}

	return &session
}

//GetAuthorizationURL Gets the request token from TM then
//generates the authorization URL.
func GetAuthorizationURL(session *TMSession) (*url.URL, error) {

	requestToken, requestSecret, err := session.Config.RequestToken()
	log.Printf("Request Token: %s\n", requestToken)
	log.Printf("Request Secret: %s\n", requestSecret)

	if err != nil {
		return nil, err
	}

	if requestToken == "" || requestSecret == "" {
		return nil, errors.New("Invalid request tokens recieved")
	}

	authorizationURL, err := session.Config.AuthorizationURL(requestToken)
	if err != nil {
		return nil, err
	}

	session.callbackServer.Register(requestToken)
	return authorizationURL, nil
}

//Authenticate waits for the server to recieve the
//authorization key then generates the access tokens.
func Authenticate(session *TMSession) error {
	log.Println("Waiting for OAuth Server Authentication....")
	verifier := session.callbackServer.WaitForOAuthVerify(session.requestToken.Token)
	accessToken, accessSecret, err := session.Config.AccessToken(session.requestToken.Token, session.requestToken.TokenSecret, verifier)

	if err != nil {
		return errors.New("Access Token Auth Failed")
	}

	log.Println("Authenticated!!")
	session.accessToken = oauth1.NewToken(accessToken, accessSecret)
	return nil
}
