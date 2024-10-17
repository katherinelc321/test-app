package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

// Retrieve configuration from environment variables
var (
	clientID     = os.Getenv("CLIENT_ID")
	clientSecret = os.Getenv("CLIENT_SECRET")
	redirectURL  = os.Getenv("REDIRECT_URL")
)

var (
	// Create an OAuth2 config object
	config = oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     microsoft.AzureADEndpoint("common"),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
)

func main() {
	// Check if environment variables are properly set
	if clientID == "" || clientSecret == "" || redirectURL == "" {
		log.Fatal("Environment variables CLIENT_ID, CLIENT_SECRET, or REDIRECT_URL are not set")
	}

	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	log.Println("Server started at http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	// Display a login link
	fmt.Fprintf(w, "<html><body><a href='/login'>Login with Entra ID</a></body></html>")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	// Redirect the user to Entra ID's login page
	authCodeURL := config.AuthCodeURL("state")
	http.Redirect(w, r, authCodeURL, http.StatusTemporaryRedirect)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	// Get the OAuth2 token from the callback request
	ctx := context.Background()
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "No code in the request", http.StatusBadRequest)
		return
	}

	// Exchange the authorization code for a token
	token, err := config.Exchange(ctx, code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set up an OpenID Connect verifier
	provider, err := oidc.NewProvider(ctx, "https://login.microsoftonline.com/<tenant-id>/v2.0")
	if err != nil {
		http.Error(w, "Failed to get provider: "+err.Error(), http.StatusInternalServerError)
		return
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
		// Skip issuer check to allow for tenant-specific issuers
		SkipIssuerCheck: true})

	// Verify the ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in token", http.StatusInternalServerError)
		return
	}

	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract user info from the ID token
	var claims struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "Failed to parse ID token claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	userEmail := claims.Email
	if userEmail == "" {
		userEmail = claims.PreferredUsername
	}

	fmt.Fprintf(w, "Hello, %s!", userEmail)
}
