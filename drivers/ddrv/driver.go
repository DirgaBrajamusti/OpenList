package ddrv

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/go-resty/resty/v2"
)

type Ddrv struct {
	model.Storage
	Addition
}

func (d *Ddrv) Config() driver.Config {
	return config
}

func (d *Ddrv) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *Ddrv) Init(ctx context.Context) error {
	// TODO login / refresh token
	//op.MustSaveDriverStorage(d)
	return nil
}

func (d *Ddrv) Drop(ctx context.Context) error {
	return nil
}

func (d *Ddrv) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	var url string
	if strings.Contains(d.Addition.Address, ",") {
		urlList := strings.Split(d.Addition.Address, ",")
		randomIndex := rand.Intn(len(urlList))
		url = urlList[randomIndex] + "/api/directories/" + dir.GetID()
	} else {

		url = d.Addition.Address + "/api/directories/" + dir.GetID()
	}

	client := resty.New()
	client.SetAuthToken(d.Addition.Token)

	resp, err := client.R().Get(url)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode() != http.StatusOK {
		return nil, errors.New(resp.String())
	}

	var response Response
	err = json.Unmarshal(resp.Body(), &response)
	if err != nil {
		return nil, err
	}

	var res []model.Obj
	for _, item := range response.Data.Files {
		if !item.IsDir {
			res = append(res, &model.Object{
				ID:       item.ID,
				Name:     item.Name,
				Path:     item.Parent,
				Size:     int64(item.Size),
				IsFolder: false,
				Modified: item.MTime,
			})
		} else {
			res = append(res, &model.Object{
				ID:       item.ID,
				Name:     item.Name,
				Path:     item.Parent,
				Size:     0,
				IsFolder: true,
				Modified: item.MTime,
			})
		}
	}
	return res, nil
}

func (d *Ddrv) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	if d.Addition.CloudflareWorkers != "" {
		url := d.Addition.CloudflareWorkers + "/" + file.GetID()

		expirySeconds := int64(3600)
		if d.CloudflareWorkersExpirySeconds != "" {
			expirySeconds, _ = strconv.ParseInt(d.Addition.CloudflareWorkersExpirySeconds, 10, 64)
		}

		generatedURL, err := GenerateCloudflareWorkersSignedURL(url, d.Addition.Token, expirySeconds)
		if err != nil {
			return nil, err
		}

		return &model.Link{
			URL: generatedURL,
		}, nil
	} else {
		var url string
		if strings.Contains(d.Addition.Address, ",") {
			urlList := strings.Split(d.Addition.Address, ",")
			randomIndex := rand.Intn(len(urlList))
			url = urlList[randomIndex]
		} else {

			url = d.Addition.Address
		}

		return &model.Link{
			URL: url + "/files/" + file.GetID(),
		}, nil
	}
}

func (d *Ddrv) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	var url string
	if strings.Contains(d.Addition.Address, ",") {
		urlList := strings.Split(d.Addition.Address, ",")
		randomIndex := rand.Intn(len(urlList))
		url = urlList[randomIndex] + "/api/directories/"
	} else {

		url = d.Addition.Address + "/api/directories/"
	}

	method := "POST"

	payload := `{"name": "` + dirName + `", "parent": "` + parentDir.GetID() + `"}`

	client := resty.New()
	client.SetAuthToken(d.Addition.Token)

	resp, err := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(payload).
		Execute(method, url)

	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusCreated {
		return errors.New(resp.String())
	}
	utils.Log.Debug(resp.String())
	return nil
}

func (d *Ddrv) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	if srcObj.IsDir() {
		var url string
		if strings.Contains(d.Addition.Address, ",") {
			urlList := strings.Split(d.Addition.Address, ",")
			randomIndex := rand.Intn(len(urlList))
			url = urlList[randomIndex] + "/api/directories/" + srcObj.GetID()
		} else {

			url = d.Addition.Address + "/api/directories/" + srcObj.GetID()
		}
		// url := d.Addition.Address + "/api/directories/" + srcObj.GetID()
		method := "PUT"

		payload := `{"name": "` + srcObj.GetName() + `", "parent": "` + dstDir.GetID() + `"}`

		client := resty.New()
		client.SetAuthToken(d.Addition.Token)

		resp, err := client.R().
			SetHeader("Content-Type", "application/json").
			SetBody(payload).
			Execute(method, url)

		if err != nil {
			return err
		}
		if resp.StatusCode() != http.StatusOK {
			return errors.New(resp.String())
		}
		utils.Log.Debug(resp.String())
		return nil
	} else {
		var url string
		if strings.Contains(d.Addition.Address, ",") {
			urlList := strings.Split(d.Addition.Address, ",")
			randomIndex := rand.Intn(len(urlList))
			url = urlList[randomIndex] + "/api/directories/" + srcObj.GetPath() + "/files/" + srcObj.GetID()
		} else {

			url = d.Addition.Address + "/api/directories/" + srcObj.GetPath() + "/files/" + srcObj.GetID()
		}
		// url := d.Addition.Address + "/api/directories/" + srcObj.GetPath() + "/files/" + srcObj.GetID()
		method := "PUT"

		payload := `{"name": "` + srcObj.GetName() + `", "parent": "` + dstDir.GetID() + `"}`

		client := resty.New()
		client.SetAuthToken(d.Addition.Token)

		resp, err := client.R().
			SetHeader("Content-Type", "application/json").
			SetBody(payload).
			Execute(method, url)

		if err != nil {
			return err
		}
		if resp.StatusCode() != http.StatusOK {
			return errors.New(resp.String())
		}
		utils.Log.Debug(resp.String())
		return nil
	}
}

func (d *Ddrv) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	if srcObj.IsDir() {
		var url string
		if strings.Contains(d.Addition.Address, ",") {
			urlList := strings.Split(d.Addition.Address, ",")
			randomIndex := rand.Intn(len(urlList))
			url = urlList[randomIndex] + "/api/directories/" + srcObj.GetID()
		} else {

			url = d.Addition.Address + "/api/directories/" + srcObj.GetID()
		}
		// url := d.Addition.Address + "/api/directories/" + srcObj.GetID()
		method := "PUT"

		payload := `{"name": "` + newName + `", "parent": "` + srcObj.GetPath() + `"}`

		client := resty.New()
		client.SetAuthToken(d.Addition.Token)

		resp, err := client.R().
			SetHeader("Content-Type", "application/json").
			SetBody(payload).
			Execute(method, url)

		if err != nil {
			return err
		}
		if resp.StatusCode() != http.StatusOK {
			return errors.New(resp.String())
		}
		utils.Log.Debug(resp.String())
		return nil
	} else {
		var url string
		if strings.Contains(d.Addition.Address, ",") {
			urlList := strings.Split(d.Addition.Address, ",")
			randomIndex := rand.Intn(len(urlList))
			url = urlList[randomIndex] + "/api/directories/" + srcObj.GetPath() + "/files/" + srcObj.GetID()
		} else {

			url = d.Addition.Address + "/api/directories/" + srcObj.GetPath() + "/files/" + srcObj.GetID()
		}
		// url := d.Addition.Address + "/api/directories/" + srcObj.GetPath() + "/files/" + srcObj.GetID()
		method := "PUT"

		payload := `{"name": "` + newName + `", "parent": "` + srcObj.GetPath() + `"}`

		client := resty.New()
		client.SetAuthToken(d.Addition.Token)

		resp, err := client.R().
			SetHeader("Content-Type", "application/json").
			SetBody(payload).
			Execute(method, url)

		if err != nil {
			return err
		}
		if resp.StatusCode() != http.StatusOK {
			return errors.New(resp.String())
		}
		utils.Log.Debug(resp.String())
		return nil
	}
}

func (d *Ddrv) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	return errs.NotSupport
}

func (d *Ddrv) Remove(ctx context.Context, obj model.Obj) error {

	if obj.IsDir() {
		var url string
		if strings.Contains(d.Addition.Address, ",") {
			urlList := strings.Split(d.Addition.Address, ",")
			randomIndex := rand.Intn(len(urlList))
			url = urlList[randomIndex] + "/api/directories/" + obj.GetID()
		} else {

			url = d.Addition.Address + "/api/directories/" + obj.GetID()
		}
		// url := d.Addition.Address + "/api/directories/" + obj.GetID()
		method := "DELETE"

		client := resty.New()
		client.SetAuthToken(d.Addition.Token)

		resp, err := client.R().
			SetHeader("Content-Type", "application/json").
			Execute(method, url)

		if err != nil {
			return err
		}
		if resp.StatusCode() != http.StatusOK {
			return errors.New(resp.String())
		}
		utils.Log.Debug(resp.String())
	} else {
		var url string
		if strings.Contains(d.Addition.Address, ",") {
			urlList := strings.Split(d.Addition.Address, ",")
			randomIndex := rand.Intn(len(urlList))
			url = urlList[randomIndex] + "/api/directories/" + obj.GetPath() + "/files/" + obj.GetID()
		} else {

			url = d.Addition.Address + "/api/directories/" + obj.GetPath() + "/files/" + obj.GetID()
		}
		// url := d.Addition.Address + "/api/directories/" + obj.GetPath() + "/files/" + obj.GetID()
		method := "DELETE"

		client := resty.New()
		client.SetAuthToken(d.Addition.Token)

		resp, err := client.R().
			SetHeader("Content-Type", "application/json").
			Execute(method, url)

		if err != nil {
			return err
		}
		if resp.StatusCode() != http.StatusOK {
			return errors.New(resp.String())
		}
		utils.Log.Debug(resp.String())
	}
	return nil
}

func (d *Ddrv) Put(ctx context.Context, dstDir model.Obj, stream model.FileStreamer, up driver.UpdateProgress) error {
	var url string
	if strings.Contains(d.Addition.Address, ",") {
		urlList := strings.Split(d.Addition.Address, ",")
		randomIndex := rand.Intn(len(urlList))
		url = urlList[randomIndex] + "/api/directories/" + dstDir.GetID() + "/files"
	} else {
		url = d.Addition.Address + "/api/directories/" + dstDir.GetID() + "/files"
	}

	// Create progress reader wrapper if progress callback is provided
	var reader io.Reader = stream
	if up != nil {
		reader = driver.NewLimitedUploadStream(ctx, &driver.ReaderUpdatingProgress{
			Reader:         stream,
			UpdateProgress: up,
		})
	}

	contentType, body := mbody(reader, stream.GetName())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, body)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Authorization", "Bearer "+d.Addition.Token)

	// Use context-aware HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return errors.New(resp.Status)
	}
	return nil
}

//func (d *Ddrv) Other(ctx context.Context, args model.OtherArgs) (interface{}, error) {
//	return nil, errs.NotSupport
//}

var _ driver.Driver = (*Ddrv)(nil)
