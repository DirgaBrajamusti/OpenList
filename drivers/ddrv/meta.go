package ddrv

import (
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
)

type Addition struct {
	// Usually one of two
	Address                        string `json:"address" required:"true"`
	Token                          string `json:"Token" required:"true"`
	CloudflareWorkers              string `json:"CloudflareWorkers" required:"false"`
	CloudflareWorkersExpirySeconds string `json:"CloudflareWorkersExpirySeconds" required:"false"`
	driver.RootID

	// Thumbnail settings
	Thumbnail        bool   `json:"thumbnail" required:"true" help:"enable thumbnail" default:"false"`
	ThumbCacheFolder string `json:"thumb_cache_folder"`
	ThumbConcurrency string `json:"thumb_concurrency" default:"16" required:"false" help:"Number of concurrent thumbnail generation goroutines. This controls how many thumbnails can be generated in parallel."`
	VideoThumbPos    string `json:"video_thumb_pos" default:"20%" required:"false" help:"The position of the video thumbnail. If the value is a number (integer or floating point), it represents the time in seconds. If the value ends with '%', it represents the percentage of the video duration."`
}

var config = driver.Config{
	Name:              "DDRV",
	LocalSort:         false,
	OnlyLocal:         false,
	NoCache:           false,
	NoUpload:          false,
	NeedMs:            false,
	DefaultRoot:       "11111111-1111-1111-1111-111111111111",
	CheckStatus:       false,
	Alert:             "",
	NoOverwriteUpload: true,
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &Ddrv{}
	})
}
