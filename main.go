package main

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/charmbracelet/log"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	"github.com/sethvargo/go-envconfig"
	"io"
	"net/http"
	"strings"
)

type Config struct {
	Secret string `env:"JWT_SECRET,required"`
}

type Headers struct {
	Authorization string `json:"authorization"`
}

type Request struct {
	Headers Headers `json:"headers"`
}

type Response struct {
	UserID string `json:"X-Hasura-User-Id"`
	Role   string `json:"X-Hasura-Role"`
}

type Claims struct {
	HasuraClaims HasuraClaims `mapstructure:"https://hasura.io/jwt/claims"`
}

type HasuraClaims struct {
	DefaultRole  string   `json:"x-hasura-default-role" mapstructure:"x-hasura-default-role"`
	AllowedRoles []string `json:"x-hasura-allowed-roles" mapstructure:"x-hasura-allowed-roles"`
	UserID       string   `json:"x-hasura-user-id" mapstructure:"x-hasura-user-id"`
}

var c Config

func main() {
	ctx := context.Background()

	if err := envconfig.Process(ctx, &c); err != nil {
		log.Fatal("unable to read config", "err", err)
	}

	http.HandleFunc("/auth", auth)

	err := http.ListenAndServe(":8091", nil)
	if err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			log.Info("server closed")
		} else {
			log.Fatalf("fatal error: %v\n", err)
		}
	}
}

func auth(w http.ResponseWriter, r *http.Request) {
	var req Request

	err := decodeJSONBody(w, r, &req)
	if err != nil {
		var malformed *malformedRequest
		if errors.As(err, &malformed) {
			w.WriteHeader(malformed.status)
			_, _ = io.WriteString(w, "unable to decode request payload")

			return
		}

		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "internal request decoding error")

		return
	}

	authHeader := req.Headers.Authorization

	if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		log.Error("unable to find auth header in POST request payload")
		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	log.Info("Verifying token", "secret", c.Secret, "header", authHeader)

	tkn, err := jwt.Parse(
		authHeader[7:],
		func(token *jwt.Token) (interface{}, error) {
			return []byte(c.Secret), nil
		},
		jwt.WithValidMethods([]string{
			"HS256",
		}),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrSignatureInvalid) {
			log.Error("unable to parse auth token; invalid signature", "err", err)
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		log.Error("unable to parse auth token", "err", err)

		w.WriteHeader(http.StatusBadRequest)

		return
	}

	if !tkn.Valid {
		log.Error("invalid auth token", "err", err)

		w.WriteHeader(http.StatusUnauthorized)

		return
	}

	tknClaims := tkn.Claims.(jwt.MapClaims)

	log.Info("found claims", "claims", tknClaims)

	var claims Claims

	err = mapstructure.Decode(tknClaims, &claims)
	if err != nil {
		log.Error("unable to decode claims", "err", err)

		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "unable to decode claims")

		return
	}

	log.Info("decoded claims", "claims", claims)

	// TODO parse the query into an AST and detect any publicly available,
	//  anonymous operations
	//  https://hasura.io/docs/latest/auth/authentication/webhook/#unauthorized-role

	userID := claims.HasuraClaims.UserID

	res := Response{
		UserID: userID,
		// TODO in the future, don't hard-code this
		Role: "teacher",
	}

	b, err := json.Marshal(res)
	if err != nil {
		log.Error("unable to marshal response", "err", err)

		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "unable to marshal response")

		return
	}

	log.Info("response", "res", res)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
