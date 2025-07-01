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
}

var config = driver.Config{
	Name:              "DDRV",
	LocalSort:         false,
	OnlyLocal:         false,
	OnlyProxy:         false,
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
