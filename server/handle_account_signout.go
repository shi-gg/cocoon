package server

import (
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleAccountSignout(e echo.Context) error {
	sess, err := session.Get(s.config.SessionCookieKey, e)
	if err != nil {
		return err
	}

	activeDid := getActiveSessionDid(sess)
	if activeDid != "" {
		removeSessionDid(sess, activeDid)
	}

	maxAge := int(AccountSessionMaxAge.Seconds())
	if len(getSessionDids(sess)) == 0 {
		maxAge = -1
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
	}

	if err := sess.Save(e.Request(), e.Response()); err != nil {
		return err
	}

	reqUri := e.QueryParam("request_uri")

	redirect := "/account/signin"
	if reqUri != "" {
		redirect += "?" + e.QueryParams().Encode()
	}

	return e.Redirect(303, redirect)
}
