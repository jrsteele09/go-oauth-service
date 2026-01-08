package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/common-nighthawk/go-figure"
	"github.com/jrsteele09/go-auth-server/auth"
	"github.com/jrsteele09/go-auth-server/auth/authflowsession"
	"github.com/jrsteele09/go-auth-server/clients"
	"github.com/jrsteele09/go-auth-server/internal/config"
	"github.com/jrsteele09/go-auth-server/server"
	"github.com/jrsteele09/go-auth-server/server/callbackstate"
	"github.com/jrsteele09/go-auth-server/server/loginsession"
	"github.com/jrsteele09/go-auth-server/tenants"
	"github.com/jrsteele09/go-auth-server/token/refresh"
	"github.com/jrsteele09/go-auth-server/users"
)

func main() {
	for {
		if err := run(); err != nil {
			log.Fatalf("Error running server: %s\n", err)
			time.Sleep(1 * time.Second)
		} else {
			break
		}
	}
	log.Printf("Server stopped\n")
}

func run() (returnError error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered from panic: %v\n", r)
			debug.PrintStack()
			returnError = errors.New("panic recovered")
		}
	}()

	c := config.New()
	displayAppname(c.GetAppName())

	// Login session repository
	loginSessionRepo, err := loginsession.NewRepoStore(c.GetDataFolder())
	if err != nil {
		return fmt.Errorf("failed to create login session repo: %w", err)
	}

	// Callback state repository
	callbackStateRepo, err := callbackstate.NewRepoStore(c.GetDataFolder())
	if err != nil {
		return fmt.Errorf("failed to create callback state repo: %w", err)
	}
	defer callbackStateRepo.Close()

	// Initialize repositories
	repos, err := createAuthRepos(c)
	if err != nil {
		return fmt.Errorf("failed to create auth repos: %w", err)
	}
	defer repos.Close()

	authServer, err := server.New(c, repos, loginSessionRepo, callbackStateRepo)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	srv := &http.Server{Addr: c.GetPort(), Handler: authServer}
	go listenAndServe(srv)
	waitForStopSignal()
	returnError = shutdown(srv)
	log.Println("Server gracefully stopped")
	return returnError
}

func listenAndServe(server *http.Server) error {
	log.Printf("Server listening on %s\n", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server.ListenAndServe %w", err)
	}
	return nil
}

func waitForStopSignal() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
}

func shutdown(server *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server.Shutdown: %w", err)
	}
	return nil
}

func displayAppname(appname string) {
	myFigure := figure.NewFigure(appname, "cybermedium", true)
	myFigure.Print()
	fmt.Println()
}

func createAuthRepos(c config.Config) (auth.Repos, error) {
	// Tenant repository
	tenantRepo, err := tenants.NewRepoStore(c.GetDataFolder())
	if err != nil {
		return auth.Repos{}, fmt.Errorf("failed to create tenant repo: %w", err)
	}

	// Auth flow session repository
	authSessionRepo, err := authflowsession.NewRepoStore(c.GetDataFolder())
	if err != nil {
		return auth.Repos{}, fmt.Errorf("failed to create auth flow session repo: %w", err)
	}

	// Client repository
	clientRepo, err := clients.NewRepoStore(c.GetDataFolder())
	if err != nil {
		return auth.Repos{}, fmt.Errorf("failed to create client repo: %w", err)
	}

	// User repository
	userRepo, err := users.NewRepoStore(c.GetDataFolder())
	if err != nil {
		return auth.Repos{}, fmt.Errorf("failed to create user repo: %w", err)
	}

	// Refresh token repository
	refreshTokenRepo, err := refresh.NewRepoStore(c.GetDataFolder())
	if err != nil {
		return auth.Repos{}, fmt.Errorf("failed to create refresh token repo: %w", err)
	}

	return auth.Repos{
		Users:         userRepo,
		AuthSession:   authSessionRepo,
		Clients:       clientRepo,
		Tenants:       tenantRepo,
		RefreshTokens: refreshTokenRepo,
	}, nil
}
