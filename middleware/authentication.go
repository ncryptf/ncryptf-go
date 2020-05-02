package middleware

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
	"context"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/jamesruan/sodium"
	"github.com/ncryptf/ncryptf-go"
)

// GetTokenFromAccessString function should return an ncryptf Token from a given access string
// Implement in client
type GetTokenFromAccessString func(accessString string) (ncryptf.Token, error)

// GetUserFromToken gets a user object from your data store, as any valid interface{} from a given Token.
// implement in client
type GetUserFromToken func(token ncryptf.Token) (interface{}, error)

// Authentication strtucture for defining ServeHttp
type Authentication struct {
	dateHeader               string
	authorizationHeader      string
	driftTimeAllowance       int
	getTokenFromAccessString GetTokenFromAccessString
	getUserFromToken         GetUserFromToken
}

// NewAuthentication provides an interface to process requests with an ncryptf formatted Authorization / HMAC header
func NewAuthentication(gtfas GetTokenFromAccessString, guft GetUserFromToken) *Authentication {
	return &Authentication{
		dateHeader:               "X-DATE",
		authorizationHeader:      "Authorization",
		driftTimeAllowance:       90,
		getTokenFromAccessString: gtfas,
		getUserFromToken:         guft,
	}
}

// ServeHTTP *next
func (a *Authentication) ServeHTTP(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	// Get a jsonAuthorization object
	params, err := ncryptf.NewAuthorizationFromString(r.Header.Get(a.authorizationHeader))

	if err == nil {
		// Get the token from the user provided function
		token, err := a.getTokenFromAccessString(params.AccessToken)
		if err == nil {
			var date time.Time
			// Parse the date header into a Go time struct
			if params.Version == 1 {
				date, err = time.Parse(time.RFC1123Z, r.Header.Get(a.dateHeader))
				if err != nil {
					a.returnError(rw)
					return
				}
			} else if params.Version == 2 {
				date, err = time.Parse(time.RFC1123Z, params.Date)
				if err != nil {
					a.returnError(rw)
					return
				}
			}

			salt, err := base64.StdEncoding.DecodeString(params.Salt)
			if err != nil {
				a.returnError(rw)
				return
			}

			auth, err := ncryptf.NewAuthorization(
				r.Method,
				a.getRequestURI(r),
				token,
				date,
				a.getRequestBody(r),
				params.Version,
				salt,
			)

			if err != nil {
				a.returnError(rw)
				return
			}

			hmac, err := base64.StdEncoding.DecodeString(params.Hmac)
			if err != nil {
				a.returnError(rw)
				return
			}

			// Validate the auth header
			if auth.Verify(hmac, *auth, a.driftTimeAllowance) {
				rawBody, err := ioutil.ReadAll(r.Body)
				if err != nil {
					a.returnError(rw)
					return
				}

				// For V2 responses validate the signature
				if len(rawBody) > 0 && r.Header.Get("Content-Type") == "application/vnd.ncryptf+json" {

					responseBodyVersion, err := ncryptf.GetVersion(rawBody)
					if err != nil {
						a.returnError(rw)
						return
					}

					if responseBodyVersion >= 2 {
						pk, err := ncryptf.GetPublicKeyFromResponse(rawBody)
						if err != nil {
							a.returnError(rw)
							return
						}

						sigpk, err := ncryptf.GetSigningPublicKeyFromResponse(rawBody)
						if err != nil {
							a.returnError(rw)
							return
						}

						if sodium.MemCmp(pk, sigpk, 32) != 0 {
							a.returnError(rw)
							return
						}
					}
				}

				user, err := a.getUserFromToken(token)
				if err != nil {
					a.returnError(rw)
					return
				}

				ctx := r.Context()
				ctx = context.WithValue(ctx, "ncryptf-token", token)
				ctx = context.WithValue(ctx, "ncryptf-user", user)

				next(rw, r.WithContext(ctx))
				return
			}
		}
	}
}

func (a *Authentication) returnError(rw http.ResponseWriter) {
	http.Error(rw, http.StatusText(401), 401)
}

func (a *Authentication) getRequestURI(r *http.Request) string {
	path := r.URL.Path
	query := r.URL.RawQuery

	if query != "" {
		return path + "?" + query
	}

	return path
}

func (a *Authentication) getRequestBody(r *http.Request) string {

	if r.Context().Value("ncryptf-decrypted-body") != nil {
		return r.Context().Value("ncryptf-decrypted-body").(string)
	}

	if b, err := ioutil.ReadAll(r.Body); err == nil {
		return string(b)
	}

	return ""
}
