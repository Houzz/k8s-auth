package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	k8s_client "k8s.io/client-go/tools/clientcmd"
	k8s_api "k8s.io/client-go/tools/clientcmd/api"

	"github.com/coreos/go-oidc"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
)

const (
	exampleAppState = "login"
)

type cluster struct {
	Cert   string `json:"certificate-authority-data"`
	Server string `json:"server"`
	Name   string `json:"name"`
}

type config struct {
	ClientID     string    `json:"client-id"`
	ClientSecret string    `json:"client-secret"`
	Issuer       string    `json:"issuer"`
	Clusters     []cluster `json:"clusters"`
	Env          string    `json:"env"`
}

type configList struct {
	Configs []config `json:"configs"`
}

type app struct {
	config
	redirectURI string
	kubeconfig  string
	debug       bool
	env         string
	profile     string
	store       string
	key         string

	verifier *oidc.IDTokenVerifier
	provider *oidc.Provider

	// Does the provider use "offline_access" scope to request a refresh token
	// or does it use "access_type=offline" (e.g. Google)?
	offlineAsScope bool

	client       *http.Client
	shutdownChan chan bool

	clusters map[string]*k8s_api.Cluster
	contexts map[string]*k8s_api.Context
}

type claim struct {
	Iss           string `json:"iss"`
	Sub           string `json:"sub"`
	Aud           string `json:"aud"`
	Exp           int    `json:"exp"`
	Iat           int    `json:"iat"`
	AtHash        string `json:"at_hash"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

// return an HTTP client which trusts the provided root CAs.
func httpClientForRootCAs(rootCAs string) (*http.Client, error) {
	tlsConfig := tls.Config{RootCAs: x509.NewCertPool()}
	rootCABytes, err := ioutil.ReadFile(rootCAs)
	if err != nil {
		return nil, fmt.Errorf("failed to read root-ca: %v", err)
	}
	if !tlsConfig.RootCAs.AppendCertsFromPEM(rootCABytes) {
		return nil, fmt.Errorf("no certs found in root CA file %q", rootCAs)
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tlsConfig,
			Proxy:           http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}, nil
}

type debugTransport struct {
	t http.RoundTripper
}

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	log.Printf("%s", reqDump)

	resp, err := d.t.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	log.Printf("%s", respDump)
	return resp, nil
}

func cmd() *cobra.Command {
	var (
		a            app
		listen       string
		tlsCert      string
		tlsKey       string
		rootCAs      string
		clusterNames []string
	)
	c := cobra.Command{
		Use:       "k8s-auth",
		Short:     "Authenticates users against OIDC and writes the required kubeconfig.",
		Long:      "",
		ValidArgs: []string{"some", "acceptable", "values"},
		RunE: func(cmd *cobra.Command, args []string) error {

			cm := NewConfigManager(&Options{a.profile})

			rawConfig, err := cm.get(a.store, a.key)

			if err != nil {
				return err
			}

			var cl configList
			if err := json.Unmarshal(rawConfig, &cl); err != nil {
				return fmt.Errorf("Failed to parse raw config file")
			}

			var c config
			for _, cfg := range cl.Configs {
				if cfg.Env == a.env {
					c = cfg
					break
				}
			}

			if c.Env != a.env {
				return fmt.Errorf("Found no given env %s in config file", a.env)
			}

			if a.Issuer == "" {
				a.Issuer = c.Issuer
			}

			if a.ClientID == "" {
				a.ClientID = c.ClientID
			}

			if a.ClientSecret == "" {
				a.ClientSecret = c.ClientSecret
			}

			memo := map[string]cluster{}

			for _, cls := range c.Clusters {
				memo[cls.Name] = cls
			}

			a.clusters = make(map[string]*k8s_api.Cluster)
			a.contexts = make(map[string]*k8s_api.Context)

			needAll := false
			for _, name := range clusterNames {
				if strings.ToLower(name) == "all" {
					needAll = true
					break
				}
			}

			if needAll {
				clusterNames = []string{}
				for name := range memo {
					clusterNames = append(clusterNames, name)
				}
			}

			for _, cn := range clusterNames {
				name := strings.ToLower(cn)
				if conf, ok := memo[name]; ok {
					finalClusterName := a.env + "-" + name
					cluster := k8s_api.NewCluster()
					cluster.Server = conf.Server
					if cert, err := base64.StdEncoding.DecodeString(conf.Cert); err != nil {
						return fmt.Errorf("Failed to decode string %s for certificate", conf.Cert)
					} else {
						cluster.CertificateAuthorityData = cert
					}
					a.clusters[finalClusterName] = cluster
					context := k8s_api.NewContext()
					context.Cluster = finalClusterName
					a.contexts[finalClusterName] = context
				} else {
					return fmt.Errorf("Found no cluster %s in config file", name)
				}
			}

			u, err := url.Parse(a.redirectURI)
			if err != nil {
				return fmt.Errorf("parse redirect-uri: %v", err)
			}
			listenURL, err := url.Parse(listen)
			if err != nil {
				return fmt.Errorf("parse listen address: %v", err)
			}

			if rootCAs != "" {
				client, cErr := httpClientForRootCAs(rootCAs)
				if cErr != nil {
					return cErr
				}
				a.client = client
			}

			if a.debug {
				if a.client == nil {
					a.client = &http.Client{
						Transport: debugTransport{http.DefaultTransport},
					}
				} else {
					a.client.Transport = debugTransport{a.client.Transport}
				}
			}

			if a.client == nil {
				a.client = http.DefaultClient
			}

			ctx := oidc.ClientContext(context.Background(), a.client)
			provider, err := oidc.NewProvider(ctx, a.Issuer)
			if err != nil {
				return fmt.Errorf("Failed to query provider %q: %v", a.Issuer, err)
			}

			var s struct {
				// What scopes does a provider support?
				//
				// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
				ScopesSupported []string `json:"scopes_supported"`
			}
			if err := provider.Claims(&s); err != nil {
				return fmt.Errorf("Failed to parse provider scopes_supported: %v", err)
			}

			if len(s.ScopesSupported) == 0 {
				// scopes_supported is a "RECOMMENDED" discovery claim, not a required
				// one. If missing, assume that the provider follows the spec and has
				// an "offline_access" scope.
				a.offlineAsScope = true
			} else {
				// See if scopes_supported has the "offline_access" scope.
				a.offlineAsScope = func() bool {
					for _, scope := range s.ScopesSupported {
						if scope == oidc.ScopeOfflineAccess {
							return true
						}
					}
					return false
				}()
			}

			a.provider = provider
			a.verifier = provider.Verifier(&oidc.Config{ClientID: a.ClientID})
			a.shutdownChan = make(chan bool)

			http.HandleFunc("/", a.handleLogin)
			http.HandleFunc(u.Path, a.handleCallback)

			switch listenURL.Scheme {
			case "http":
				log.Printf("listening on %s", listen)
				go open(listen)
				go a.waitShutdown()
				return http.ListenAndServe(listenURL.Host, nil)
			case "https":
				log.Printf("listening on %s", listen)
				go open(listen)
				go a.waitShutdown()
				return http.ListenAndServeTLS(listenURL.Host, tlsCert, tlsKey, nil)
			default:
				return fmt.Errorf("listen address %q is not using http or https", listen)
			}
		},
	}

	// Configurable variables
	c.Flags().StringVar(&a.ClientID, "client-id", "", "OAuth2 client ID of this application.")
	c.Flags().StringVar(&a.ClientSecret, "client-secret", "", "OAuth2 client secret of this application.")
	c.Flags().StringVar(&a.redirectURI, "redirect-uri", "http://127.0.0.1:5555/callback", "Callback URL for OAuth2 responses.")
	c.Flags().StringVar(&a.Issuer, "issuer", "", "URL of the OpenID Connect issuer.")
	c.Flags().StringVar(&listen, "listen", "http://127.0.0.1:5555", "HTTP(S) address to listen at.")
	c.Flags().StringVar(&tlsCert, "tls-cert", "", "X509 cert file to present when serving HTTPS.")
	c.Flags().StringVar(&tlsKey, "tls-key", "", "Private key for the HTTPS cert.")
	c.Flags().StringVar(&rootCAs, "issuer-root-ca", "", "Root certificate authorities for the issuer. Defaults to host certs.")
	c.Flags().BoolVar(&a.debug, "debug", false, "Print all request and responses from the OpenID Connect issuer.")
	c.Flags().StringVar(&a.kubeconfig, "kubeconfig", "", "Kubeconfig file to configure.")
	c.Flags().StringSliceVar(&clusterNames, "cluster", []string{}, "Functionality of cluster to access to, e.g. batch, saas, and main etc.")
	c.Flags().StringVar(&a.env, "env", "stg", "Enviroment where authentication system is going to be run against. Choose from stg and prod.")
	c.Flags().StringVar(&a.profile, "profile", "staging", "Profile of AWS credentials to load.")
	c.Flags().StringVar(&a.store, "store", "", "Storage of the configuration file. In S3, it's the bucket name.")
	c.Flags().StringVar(&a.key, "key", "", "Key of the configuration file. In S3, it's the object key.")
	return &c
}

func main() {
	if err := cmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
}

func (a *app) oauth2Config(scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.ClientID,
		ClientSecret: a.ClientSecret,
		Endpoint:     a.provider.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  a.redirectURI,
	}
}

func (a *app) handleLogin(w http.ResponseWriter, r *http.Request) {
	var scopes []string

	var authCodeURL string
	scopes = append(scopes, "groups", "openid", "profile", "email")
	if a.offlineAsScope {
		scopes = append(scopes, "offline_access")
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(exampleAppState)
	} else {
		authCodeURL = a.oauth2Config(scopes).AuthCodeURL(exampleAppState, oauth2.AccessTypeOffline)
	}

	http.Redirect(w, r, authCodeURL, http.StatusSeeOther)
}

func (a *app) handleCallback(w http.ResponseWriter, r *http.Request) {
	var (
		err   error
		token *oauth2.Token
	)

	ctx := oidc.ClientContext(r.Context(), a.client)
	oauth2Config := a.oauth2Config(nil)
	switch r.Method {
	case "GET":
		// Authorization redirect callback from OAuth2 auth flow.
		if errMsg := r.FormValue("error"); errMsg != "" {
			http.Error(w, errMsg+": "+r.FormValue("error_description"), http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		if code == "" {
			http.Error(w, fmt.Sprintf("no code in request: %q", r.Form), http.StatusBadRequest)
			return
		}
		if state := r.FormValue("state"); state != exampleAppState {
			http.Error(w, fmt.Sprintf("expected state %q got %q", exampleAppState, state), http.StatusBadRequest)
			return
		}
		token, err = oauth2Config.Exchange(ctx, code)
	case "POST":
		// Form request from frontend to refresh a token.
		refresh := r.FormValue("refresh_token")
		if refresh == "" {
			http.Error(w, fmt.Sprintf("no refresh_token in request: %q", r.Form), http.StatusBadRequest)
			return
		}
		t := &oauth2.Token{
			RefreshToken: refresh,
			Expiry:       time.Now().Add(-time.Hour),
		}
		token, err = oauth2Config.TokenSource(ctx, t).Token()
	default:
		http.Error(w, fmt.Sprintf("method not implemented: %s", r.Method), http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get token: %v", err), http.StatusInternalServerError)
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "no id_token in token response", http.StatusInternalServerError)
		return
	}

	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to verify ID token: %v", err), http.StatusInternalServerError)
		return
	}
	var claims json.RawMessage
	idToken.Claims(&claims)

	buff := new(bytes.Buffer)
	json.Indent(buff, []byte(claims), "", "  ")
	var m claim
	err = json.Unmarshal(claims, &m)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read claims: %v", err), http.StatusInternalServerError)
		go func() {
			a.shutdownChan <- true
		}()
		return
	}

	err = updateKubeConfig(rawIDToken, token.RefreshToken, m, a)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to update kubeconfig: %v", err), http.StatusInternalServerError)
		go func() {
			a.shutdownChan <- true
		}()
		return
	}

	renderToken(w, a.redirectURI, rawIDToken, token.RefreshToken, buff.Bytes(), a.debug)
	fmt.Printf("Login Succeeded as %s\n", m.Email)
	if a.debug {
		fmt.Printf("ID Token: %s\n", rawIDToken)
		fmt.Printf("Refresh Token: %s\n", token.RefreshToken)
		fmt.Printf("Claims: %s\n", string(claims))
	}

	go func() {
		a.shutdownChan <- true
	}()
}

func (a *app) waitShutdown() {
	irqSig := make(chan os.Signal, 1)
	signal.Notify(irqSig, syscall.SIGINT, syscall.SIGTERM)

	//Wait interrupt or shutdown request through /shutdown
	select {
	case sig := <-irqSig:
		log.Printf("Shutdown request (signal: %v)", sig)
		os.Exit(0)
	case <-a.shutdownChan:
		os.Exit(0)
	}
}

func updateKubeConfig(IDToken string, refreshToken string, claims claim, a *app) error {
	var config *k8s_api.Config
	var outputFilename string
	var err error

	clientConfigLoadingRules := k8s_client.NewDefaultClientConfigLoadingRules()

	if a.kubeconfig != "" {
		if _, err = os.Stat(a.kubeconfig); os.IsNotExist(err) {
			config = k8s_api.NewConfig()
			err = nil
		} else {
			clientConfigLoadingRules.ExplicitPath = a.kubeconfig
			config, err = clientConfigLoadingRules.Load()
		}
		outputFilename = a.kubeconfig
	} else {
		config, err = clientConfigLoadingRules.Load()
		outputFilename = k8s_client.RecommendedHomeFile
		if !k8s_api.IsConfigEmpty(config) {
			outputFilename = clientConfigLoadingRules.GetDefaultFilename()
		}
	}
	if err != nil {
		return err
	}

	for k, v := range a.clusters {
		config.Clusters[k] = v
	}
	for k, v := range a.contexts {
		config.Contexts[k] = v
	}

	authInfo := k8s_api.NewAuthInfo()
	if conf, ok := config.AuthInfos[claims.Email]; ok {
		authInfo = conf
	}

	authInfo.AuthProvider = &k8s_api.AuthProviderConfig{
		Name: "oidc",
		Config: map[string]string{
			"client-id":      a.ClientID,
			"client-secret":  a.ClientSecret,
			"id-token":       IDToken,
			"refresh-token":  refreshToken,
			"idp-issuer-url": claims.Iss,
		},
	}

	finalUserName := a.env + "-" + claims.Email

	config.AuthInfos[finalUserName] = authInfo

	for _, context := range a.contexts {
		context.AuthInfo = finalUserName
	}

	fmt.Printf("Writing config to %s\n", outputFilename)
	err = k8s_client.WriteToFile(*config, outputFilename)
	if err != nil {
		return err
	}
	return nil
}

func open(url string) error {

	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}
