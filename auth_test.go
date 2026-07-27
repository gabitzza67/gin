// Copyright 2014 Manu Martinez-Almeida. All rights reserved.
// Use of this source code is governed by a MIT style
// license that can be found in the LICENSE file.

package gin

import (
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

type closeTrackingBody struct {
	closed bool
	data   []byte
	read   int
}

func (c *closeTrackingBody) Read(p []byte) (n int, err error) {
	if c.read >= len(c.data) {
		return 0, io.EOF
	}
	n = copy(p, c.data[c.read:])
	c.read += n
	return n, nil
}

func (c *closeTrackingBody) Close() error {
	c.closed = true
	return nil
}

func TestBasicAuth(t *testing.T) {
	pairs := processAccounts(Accounts{
		"admin": "password",
	})

	assert.Len(t, pairs, 1)
	assert.Equal(t, authorizationHeader("admin", "password"), pairs[0].value)

	router := New()
	router.Use(BasicAuth(Accounts{
		"admin": "password",
		"foo":   "bar",
	}))

	router.GET("/login", func(c *Context) {
		c.String(http.StatusOK, c.MustGet(AuthUserKey).(string))
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/login", nil)
	req.Header.Set("Authorization", authorizationHeader("admin", "password"))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "admin", w.Body.String())

	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/login", nil)
	req.Header.Set("Authorization", authorizationHeader("foo", "bar"))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "foo", w.Body.String())

	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/login", nil)
	req.Header.Set("Authorization", authorizationHeader("admin", "wrong"))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, "Basic realm=\"Authorization Required\"", w.Header().Get("WWW-Authenticate"))
}

func TestBasicAuthBodyClosed(t *testing.T) {
	router := New()
	router.Use(BasicAuth(Accounts{
		"admin": "password",
	}))

	router.POST("/login", func(c *Context) {
		c.String(http.StatusOK, "ok")
	})

	body := &closeTrackingBody{data: []byte("some body data")}
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", body)
	req.Header.Set("Authorization", authorizationHeader("admin", "wrong"))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.True(t, body.closed)
}

func TestBasicAuthBodyNotClosedOnSuccess(t *testing.T) {
	router := New()
	router.Use(BasicAuth(Accounts{
		"admin": "password",
	}))

	router.POST("/login", func(c *Context) {
		c.String(http.StatusOK, "ok")
	})

	body := &closeTrackingBody{data: []byte("some body data")}
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", body)
	req.Header.Set("Authorization", authorizationHeader("admin", "password"))
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.False(t, body.closed)
}
