package server

import (
	"io"

	"github.com/bluesky-social/indigo/carstore"
	"github.com/haileyok/cocoon/internal/helpers"
	"github.com/haileyok/cocoon/models"
	"github.com/ipfs/go-cid"
	cbor "github.com/ipfs/go-ipld-cbor"
	"github.com/ipld/go-car"
	"github.com/labstack/echo/v4"
)

func (s *Server) handleSyncGetRepo(e echo.Context) error {
	ctx := e.Request().Context()
	logger := s.logger.With("name", "handleSyncGetRepo")

	did := e.QueryParam("did")
	if did == "" {
		return helpers.InputError(e, nil)
	}

	urepo, err := s.getRepoActorByDid(ctx, did)
	if err != nil {
		return err
	}

	rc, err := cid.Cast(urepo.Root)
	if err != nil {
		return err
	}

	hb, err := cbor.DumpObject(&car.CarHeader{
		Roots:   []cid.Cid{rc},
		Version: 1,
	})

	if err != nil {
		return err
	}

	r, w := io.Pipe()
	go func() {
		var writeErr error
		writeErr = streamCar(w, s, urepo.Repo.Did, hb)
		if writeErr != nil {
			logger.Error("error streaming car", "error", writeErr)
		}
		w.CloseWithError(writeErr)
	}()

	return e.Stream(200, "application/vnd.ipld.car", r)
}

func streamCar(w io.Writer, s *Server, did string, hb []byte) error {
	if _, err := carstore.LdWrite(w, hb); err != nil {
		return err
	}

	rows, err := s.db.Client().
		Model(&models.Block{}).
		Where("did = ?", did).
		Order("rev ASC").
		Rows()
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var block models.Block
		if err := s.db.Client().ScanRows(rows, &block); err != nil {
			return err
		}
		if _, err := carstore.LdWrite(w, block.Cid, block.Value); err != nil {
			return err
		}
	}

	return rows.Err()
}
