package tmoauth

import (
	"errors"
	"fmt"
	"log"

	"tmapi/config"
	"tmapi/tmfuncs"

	"github.com/dghubble/oauth1"
)

func openBrowser(url string) {
	fmt.Println("Trying to redirect browser...")
	redirectAddr <- url
}

//MakeNewTMSession func
func MakeNewTMSession() (*tmfuncs.TMSession, error) {

	session := tmfuncs.TMSession{}
	log.Printf("Website Selected: %s\n", config.Settings.Host)

	session.TradeMeEndpoint = oauth1.Endpoint{
		RequestTokenURL: config.Settings.Endpoint.RequestTokenURL,
		AuthorizeURL:    config.Settings.Endpoint.AuthorizeURL,
		AccessTokenURL:  config.Settings.Endpoint.AccessTokenURL,
	}

	log.Printf("Request Token URL: %s\n", session.TradeMeEndpoint.RequestTokenURL)

	session.Config = oauth1.NewConfig(config.Settings.ConsumerKey, config.Settings.ConsumerSecret)
	session.Config.CallbackURL = config.Settings.CallbackURL
	session.Config.Endpoint = session.TradeMeEndpoint

	err := Login(&session)
	if err != nil {
		return nil, err
	}

	err = Authenticate(&session)
	session.GenHTTPClient()

	return &session, err
}

//Login func
func Login(session *tmfuncs.TMSession) error {

	requestToken, requestSecret, err := session.Config.RequestToken()
	log.Printf("Request Token: %s\n", requestToken)
	log.Printf("Request Secret: %s\n", requestSecret)

	if err != nil {
		return err
	}

	if requestToken == "" || requestSecret == "" {
		return errors.New("Invalid request tokens recieved")
	}

	authorizationURL, err := session.Config.AuthorizationURL(requestToken)
	if err != nil {
		return err
	}

	log.Printf("Opening Authorization URL in Browser: %s\n", authorizationURL.String())
	openBrowser(authorizationURL.String())

	session.RequestToken = oauth1.NewToken(requestToken, requestSecret)
	return nil
}

//Authenticate func
func Authenticate(session *tmfuncs.TMSession) error {
	log.Println("Waiting for OAuth Server Authentication....")

	verifier := WaitForOauthVerify()
	accessToken, accessSecret, err := session.Config.AccessToken(session.RequestToken.Token, session.RequestToken.TokenSecret, verifier)

	if err != nil {
		return errors.New("Access Token Auth Failed")
	}

	log.Println("Authenticated!!")
	session.AccessToken = oauth1.NewToken(accessToken, accessSecret)
	return nil
}
