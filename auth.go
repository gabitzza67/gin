// Copyright 2014 Manu Martinez-Almeida. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package gin

import (
	"crypto/subtle"
	"encoding/base64"
	"io"
	"net/http"
)

// AuthUserKey is the cookie name for user credential in basic auth.
const AuthUserKey = "user"

// Accounts is a shortcut for map[string]string
type Accounts map[string]string

// BasicAuthForRealm returns a gin.HandlerFunc ...
func BasicAuthForRealm(accounts Accounts, realm string) HandlerFunc {
	if realm == "" {
		realm = "Basic realm=\"Authorization Required\""
	} else {
		realm = "Basic realm=\"" + realm + "\""
	}

	return func(c *Context) {
		user, password, hasAuth := c.Request.BasicAuth()
		if hasAuth {
			if secret, ok := accounts[user]; ok {
				if subtle.ConstantTimeCompare([]byte(secret), []byte(password)) == 1 {
					c.Set(AuthUserKey, user)
					return
				}
			}
		}

		c.Header("WWW-Authenticate", realm)
		if c.Request != nil && c.Request.Body != nil {
			_, _ = io.CopyN(io.Discard, c.Request.Body, 4096)
			c.Request.Body.Close()
		}
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

// BasicAuth returns a gin.HandlerFunc ...
func BasicAuth(accounts Accounts) HandlerFunc {
	return BasicAuthForRealm(accounts, "")
}
