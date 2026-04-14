package server

import (
	"net/url"
	"slices"
	"strings"

	"github.com/Azure/go-autorest/autorest/to"
	"github.com/gorilla/sessions"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

type AccountSwitchRequest struct {
	Did         string `form:"did"`
	QueryParams string `form:"query_params"`
	Next        string `form:"next"`
}

func sanitizeLocalRedirectPath(next string) string {
	redirect := strings.TrimSpace(next)
	if redirect == "" {
		return "/account"
	}
	if !strings.HasPrefix(redirect, "/") || strings.HasPrefix(redirect, "//") {
		return "/account"
	}

	parsed, err := url.Parse(redirect)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return "/account"
	}

	return redirect
}

func (s *Server) handleAccountSwitchPost(e echo.Context) error {
	var req AccountSwitchRequest
	if err := e.Bind(&req); err != nil {
		return helpers.InputError(e, to.StringPtr("invalid switch account request"))
	}

	sess, err := session.Get(s.config.SessionCookieKey, e)
	if err != nil {
		return err
	}

	dids := getSessionDids(sess)
	if !slices.Contains(dids, req.Did) {
		return helpers.InputError(e, to.StringPtr("requested account is not logged in"))
	}

	setActiveSessionDid(sess, req.Did)
	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(AccountSessionMaxAge.Seconds()),
		HttpOnly: true,
	}

	if err := sess.Save(e.Request(), e.Response()); err != nil {
		return err
	}

	redirect := sanitizeLocalRedirectPath(req.Next)
	if req.QueryParams != "" {
		redirect += "?" + req.QueryParams
	}

	return e.Redirect(303, redirect)
}
