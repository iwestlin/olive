package show

import (
	"github.com/go-olive/olive/business/core/show/db"
	"github.com/go-olive/olive/engine/kernel"
)

// Show represents an individual show.
type Show = kernel.Show

// NewShow contains information needed to create a new Show.
type NewShow struct {
	Enable       bool   `json:"enable"`
	Platform     string `json:"platform" validate:"required"`
	RoomID       string `json:"room_id" validate:"required"`
	StreamerName string `json:"streamer_name"`
	OutTmpl      string `json:"out_tmpl"`
	Parser       string `json:"parser"`
	SaveDir      string `json:"save_dir"`
	PostCmds     string `json:"post_cmds"`
	SplitRule    string `json:"split_rule"`
}

// UpdateShow defines what information may be provided to modify an existing
// Show. All fields are optional so clients can send just the fields they want
// changed. It uses pointer fields so we can differentiate between a field that
// was not provided and a field that was provided as explicitly blank. Normally
// we do not want to use pointers to basic types but we make exceptions around
// marshalling/unmarshalling.
type UpdateShow struct {
	Enable       *bool   `json:"enable"`
	Platform     *string `json:"platform"`
	RoomID       *string `json:"room_id"`
	StreamerName *string `json:"streamer_name"`
	OutTmpl      *string `json:"out_tmpl"`
	Parser       *string `json:"parser"`
	SaveDir      *string `json:"save_dir"`
	PostCmds     *string `json:"post_cmds"`
	SplitRule    *string `json:"split_rule"`
}

// =============================================================================

// toShow converts a DB-row Show into the kernel Show type that the engine
// consumes. Historically this used unsafe.Pointer to alias the two structs,
// but that relied on the engine and the DB layer jamais diverging in field
// order/layout; an invisible field reorder would have produced memory
// corruption. The explicit copy below is immune to that class of bug while
// staying zero-cost in practice.
func toShow(dbShow db.Show) Show {
	return Show{
		ID:           dbShow.ID,
		Enable:       dbShow.Enable,
		Platform:     dbShow.Platform,
		RoomID:       dbShow.RoomID,
		StreamerName: dbShow.StreamerName,
		OutTmpl:      dbShow.OutTmpl,
		Parser:       dbShow.Parser,
		SaveDir:      dbShow.SaveDir,
		PostCmds:     dbShow.PostCmds,
		SplitRule:    dbShow.SplitRule,
		DateCreated:  dbShow.DateCreated,
		DateUpdated:  dbShow.DateUpdated,
	}
}

func toShowSlice(dbShows []db.Show) []Show {
	Shows := make([]Show, len(dbShows))
	for i, dbShow := range dbShows {
		Shows[i] = toShow(dbShow)
	}
	return Shows
}