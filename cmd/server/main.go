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
	sessionrepofakes "github.com/jrsteele09/go-auth-server/auth/sessions/repofakes"
	fakeclientrepo "github.com/jrsteele09/go-auth-server/clients/fakerepo"
	"github.com/jrsteele09/go-auth-server/internal/config"
	"github.com/jrsteele09/go-auth-server/server"
	"github.com/jrsteele09/go-auth-server/server/authflowrepo"
	"github.com/jrsteele09/go-auth-server/server/loginsession"
	tenantrepofakes "github.com/jrsteele09/go-auth-server/tenants/repofakes"
	refreshrepofake "github.com/jrsteele09/go-auth-server/token/refresh/repofake"
	fakeuserrepo "github.com/jrsteele09/go-auth-server/users/repofake"
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

	// Initialize repositories (using in-memory fake implementations for development)
	repos := auth.Repos{
		Users:         fakeuserrepo.NewFakeUserRepo(),
		Sessions:      sessionrepofakes.NewFakeSessionRepo(),
		Clients:       fakeclientrepo.NewFakeClientRepo(),
		Tenants:       tenantrepofakes.NewFakeTenantRepo(),
		RefreshTokens: refreshrepofake.NewFakeRefreshTokenRepo(),
	}

	loginSessionRepo := loginsession.NewInMemoryLoginSessionRepo()
	authStateRepo := authflowrepo.NewInMemoryRepo()

	authServer, err := server.New(c, repos, loginSessionRepo, authStateRepo)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	srv := &http.Server{Addr: c.GetPort(), Handler: authServer}
	go listenAndServe(srv)
	waitForStopSignal()
	returnError = shutdown(srv)
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
