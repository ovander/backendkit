// Command socrate-seed writes the fixtures the backendkit conformance suite
// needs into a scratch Socrate database: three confidential clients and one
// verified user per suite package, a member of every client.
//
// It is not part of the backendkit module (it sits under testdata, which the go
// tool ignores). scripts/conformance-local.sh and the Conformance workflow copy
// it into a Socrate source tree and run it there, because it builds on
// Socrate's own model and hashing (internal packages), exactly like Socrate's
// deploy/perf/seed: a client secret or password hash written by Socrate's code
// is one Socrate accepts.
//
// Every secret comes from the environment, generated per run by the caller;
// nothing here is a credential. Point it only at a throwaway database: it
// refuses to run when the fixture clients already exist.
//
// Environment:
//
//	DATABASE_URL                 the scratch Socrate database (migrated)
//	CONFORMANCE_PLAIN_CLIENT_ID   no registered audience, no claim mapping
//	CONFORMANCE_PLAIN_CLIENT_SECRET
//	CONFORMANCE_DUAL_CLIENT_ID    one registered audience, no claim mapping
//	CONFORMANCE_DUAL_CLIENT_SECRET
//	CONFORMANCE_CLAIMS_CLIENT_ID  claim mappings, no registered audience
//	CONFORMANCE_CLAIMS_CLIENT_SECRET
//	CONFORMANCE_REDIRECT_URI      the redirect URI every client registers
//	CONFORMANCE_AUDIENCE          the audience registered on the dual client
//	CONFORMANCE_TENANT_ID         the UUID the claims client's literal mapping issues
//	CONFORMANCE_USER_PASSWORD    password of every fixture user
//	CONFORMANCE_USERS            comma-separated user names; each becomes
//	                             <name>@example.test
package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"
)

func mustEnv(name string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		log.Fatalf("%s is required", name)
	}
	return v
}

func main() {
	db, err := gorm.Open(postgres.Open(mustEnv("DATABASE_URL")), &gorm.Config{
		Logger: glogger.Default.LogMode(glogger.Silent),
	})
	if err != nil {
		log.Fatalf("connect: %v", err)
	}

	plainID := mustEnv("CONFORMANCE_PLAIN_CLIENT_ID")
	dualID := mustEnv("CONFORMANCE_DUAL_CLIENT_ID")
	claimsID := mustEnv("CONFORMANCE_CLAIMS_CLIENT_ID")
	ids := []string{plainID, dualID, claimsID}
	var existing int64
	if err := db.Model(&model.App{}).Where("client_id IN ?", ids).Count(&existing).Error; err != nil {
		log.Fatalf("check existing clients: %v", err)
	}
	if existing > 0 {
		log.Fatalf("the conformance clients already exist: seed a fresh database")
	}

	now := time.Now()
	redirect := mustEnv("CONFORMANCE_REDIRECT_URI")
	newClient := func(name, clientID, secretEnv string) *model.App {
		return &model.App{
			Name: name, ClientID: clientID, ClientSecretHash: hashSecret(mustEnv(secretEnv)),
			Active: true, RequirePKCE: true, RedirectURIs: model.StringArray{redirect},
			CreatedAt: now, UpdatedAt: now,
		}
	}

	plain := newClient("backendkit conformance (plain)", plainID, "CONFORMANCE_PLAIN_CLIENT_SECRET")
	dual := newClient("backendkit conformance (audience)", dualID, "CONFORMANCE_DUAL_CLIENT_SECRET")
	dual.Audiences = model.StringArray{mustEnv("CONFORMANCE_AUDIENCE")}
	claims := newClient("backendkit conformance (claims)", claimsID, "CONFORMANCE_CLAIMS_CLIENT_SECRET")
	claims.ClaimMappings = model.ClaimMappings{
		// A literal (tenant) claim in both tokens, as the OP contract
		// recommends for per-tenant service accounts.
		"tenant_id": {Source: model.ClaimSourceLiteralPrefix + mustEnv("CONFORMANCE_TENANT_ID"), Target: model.ClaimTargetBoth},
		// A user attribute, in the access token only.
		"department": {Source: model.ClaimSourceUserAttrPrefix + "department", Target: model.ClaimTargetAccess},
		// An app-sourced claim, which client_credentials tokens carry too.
		"client": {Source: model.ClaimSourceAppClientID, Target: model.ClaimTargetAccess},
	}
	apps := []*model.App{plain, dual, claims}
	for _, app := range apps {
		if err := db.Create(app).Error; err != nil {
			log.Fatalf("create client %s: %v", app.ClientID, err)
		}
	}

	passwordHash, err := auth.HashPassword(mustEnv("CONFORMANCE_USER_PASSWORD"))
	if err != nil {
		log.Fatalf("hash password: %v", err)
	}
	var emails []string
	for _, name := range strings.Split(mustEnv("CONFORMANCE_USERS"), ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		user := &model.User{
			Name: "Conformance " + name, Email: name + "@example.test", HashedPassword: passwordHash,
			IsVerified: true, Role: model.UserRoleUser, TokenVersion: 1, Source: "conformance-seed",
			Attributes:  model.JSONMap{"department": "research"},
			ConfirmedAt: &now, CreatedAt: now, UpdatedAt: now,
		}
		if err := db.Create(user).Error; err != nil {
			log.Fatalf("create user %s: %v", user.Email, err)
		}
		for _, app := range apps {
			role := &model.UserAppRole{UserID: user.ID, AppID: app.ID, Role: "user", CreatedAt: now, UpdatedAt: now}
			if err := db.Create(role).Error; err != nil {
				log.Fatalf("grant %s a role in %s: %v", user.Email, app.ClientID, err)
			}
		}
		emails = append(emails, user.Email)
	}

	for _, app := range apps {
		fmt.Printf("seeded client %s (app:%d)\n", app.ClientID, app.ID)
	}
	fmt.Printf("seeded users %s\n", strings.Join(emails, ", "))
}

func hashSecret(secret string) string {
	h, err := auth.HashClientSecret(secret)
	if err != nil {
		log.Fatalf("hash client secret: %v", err)
	}
	return h
}
