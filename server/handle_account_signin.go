package server

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/gorilla/sessions"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type OauthSigninInput struct {
	Username        string `form:"username"`
	Password        string `form:"password"`
	AuthFactorToken string `form:"token"`
	QueryParams     string `form:"query_params"`
}

var ErrSessionUnauthenticated = errors.New("session is unauthenticated")

func (s *Server) getSessionRepoAndAccountsOrErr(e echo.Context) (*models.RepoActor, *sessions.Session, []models.RepoActor, error) {
	ctx := e.Request().Context()

	sess, err := session.Get(s.config.SessionCookieKey, e)
	if err != nil {
		return nil, nil, nil, err
	}

	accounts, changed, err := s.getSessionAccountActors(ctx, sess)
	if err != nil {
		return nil, sess, nil, err
	}
	if changed {
		if err := sess.Save(e.Request(), e.Response()); err != nil {
			return nil, sess, nil, err
		}
	}

	did := getActiveSessionDid(sess)
	if did == "" {
		return nil, sess, accounts, fmt.Errorf("%w: did was not set in session", ErrSessionUnauthenticated)
	}

	for _, account := range accounts {
		if account.Repo.Did == did {
			return &account, sess, accounts, nil
		}
	}

	return nil, sess, accounts, fmt.Errorf("%w: did was not found in session accounts", ErrSessionUnauthenticated)
}

func (s *Server) getSessionRepoOrErr(e echo.Context) (*models.RepoActor, *sessions.Session, error) {
	repo, sess, _, err := s.getSessionRepoAndAccountsOrErr(e)
	return repo, sess, err
}

func getFlashesFromSession(e echo.Context, sess *sessions.Session) map[string]any {
	defer sess.Save(e.Request(), e.Response())
	return map[string]any{
		"errors":        sess.Flashes("error"),
		"successes":     sess.Flashes("success"),
		"tokenrequired": sess.Flashes("tokenrequired"),
	}
}

func (s *Server) handleAccountSigninGet(e echo.Context) error {
	repo, sess, accounts, err := s.getSessionRepoAndAccountsOrErr(e)
	if err != nil && !errors.Is(err, ErrSessionUnauthenticated) {
		return helpers.ServerError(e, nil)
	}
	if err == nil && e.QueryString() == "" {
		return e.Redirect(303, "/account")
	}

	if sess == nil {
		return helpers.ServerError(e, nil)
	}

	activeDid := ""
	if repo != nil {
		activeDid = repo.Repo.Did
	}

	return e.Render(200, "signin.html", map[string]any{
		"flashes":     getFlashesFromSession(e, sess),
		"QueryParams": e.QueryParams().Encode(),
		"Accounts":    accounts,
		"ActiveDid":   activeDid,
	})
}

func (s *Server) handleAccountSigninPost(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleAccountSigninPost")

	var req OauthSigninInput
	if err := e.Bind(&req); err != nil {
		logger.Error("error binding sign in req", "error", err)
		return helpers.ServerError(e, nil)
	}

	sess, _ := session.Get(s.config.SessionCookieKey, e)

	req.Username = strings.ToLower(req.Username)
	var idtype string
	if _, err := syntax.ParseDID(req.Username); err == nil {
		idtype = "did"
	} else if _, err := syntax.ParseHandle(req.Username); err == nil {
		idtype = "handle"
	} else {
		idtype = "email"
	}

	queryParams := ""
	if req.QueryParams != "" {
		queryParams = fmt.Sprintf("?%s", req.QueryParams)
	}

	// TODO: we should make this a helper since we do it for the base create_session as well
	var repo models.RepoActor
	var err error
	switch idtype {
	case "did":
		err = s.db.Raw(ctx, "SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.did = ?", nil, req.Username).Scan(&repo).Error
	case "handle":
		err = s.db.Raw(ctx, "SELECT r.*, a.* FROM actors a LEFT JOIN repos r ON a.did = r.did WHERE a.handle = ?", nil, req.Username).Scan(&repo).Error
	case "email":
		err = s.db.Raw(ctx, "SELECT r.*, a.* FROM repos r LEFT JOIN actors a ON r.did = a.did WHERE r.email = ?", nil, req.Username).Scan(&repo).Error
	}
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			sess.AddFlash("Handle or password is incorrect", "error")
		} else {
			sess.AddFlash("Something went wrong!", "error")
		}
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account/signin"+queryParams)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(repo.Password), []byte(req.Password)); err != nil {
		if err != bcrypt.ErrMismatchedHashAndPassword {
			sess.AddFlash("Handle or password is incorrect", "error")
		} else {
			sess.AddFlash("Something went wrong!", "error")
		}
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account/signin"+queryParams)
	}

	// if repo requires 2FA token and one hasn't been provided, return error prompting for one
	if repo.TwoFactorType != models.TwoFactorTypeNone && req.AuthFactorToken == "" {
		err = s.createAndSendTwoFactorCode(ctx, repo)
		if err != nil {
			sess.AddFlash("Something went wrong!", "error")
			sess.Save(e.Request(), e.Response())
			return e.Redirect(303, "/account/signin"+queryParams)
		}

		sess.AddFlash("requires 2FA token", "tokenrequired")
		sess.Save(e.Request(), e.Response())
		return e.Redirect(303, "/account/signin"+queryParams)
	}

	// if 2FAis required, now check that the one provided is valid
	if repo.TwoFactorType != models.TwoFactorTypeNone {
		if repo.TwoFactorCode == nil || repo.TwoFactorCodeExpiresAt == nil {
			err = s.createAndSendTwoFactorCode(ctx, repo)
			if err != nil {
				sess.AddFlash("Something went wrong!", "error")
				sess.Save(e.Request(), e.Response())
				return e.Redirect(303, "/account/signin"+queryParams)
			}

			sess.AddFlash("requires 2FA token", "tokenrequired")
			sess.Save(e.Request(), e.Response())
			return e.Redirect(303, "/account/signin"+queryParams)
		}

		if *repo.TwoFactorCode != req.AuthFactorToken {
			return helpers.InvalidTokenError(e)
		}

		if time.Now().UTC().After(*repo.TwoFactorCodeExpiresAt) {
			return helpers.ExpiredTokenError(e)
		}
	}

	sess.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   int(AccountSessionMaxAge.Seconds()),
		HttpOnly: true,
	}

	setActiveSessionDid(sess, repo.Repo.Did)

	if err := sess.Save(e.Request(), e.Response()); err != nil {
		return err
	}

	if queryParams != "" {
		return e.Redirect(303, "/oauth/authorize"+queryParams)
	} else {
		return e.Redirect(303, "/account")
	}
}
