package ddrv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	stdpath "path"
	"strconv"
	"strings"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/sign"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/server/common"
	"github.com/go-resty/resty/v2"
)

type Ddrv struct {
	model.Storage
	Addition

	// Thumbnail settings
	thumbConcurrency          int
	thumbTokenBucket          TokenBucket
	videoThumbPos             float64
	videoThumbPosIsPercentage bool
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

	// Thumbnail configuration
	if d.ThumbCacheFolder != "" && !utils.Exists(d.ThumbCacheFolder) {
		err := os.MkdirAll(d.ThumbCacheFolder, 0777)
		if err != nil {
			return err
		}
	}
	if d.ThumbConcurrency != "" {
		v, err := strconv.ParseUint(d.ThumbConcurrency, 10, 32)
		if err != nil {
			return err
		}
		d.thumbConcurrency = int(v)
	}
	if d.thumbConcurrency == 0 {
		d.thumbTokenBucket = NewNopTokenBucket()
	} else {
		d.thumbTokenBucket = NewStaticTokenBucketWithMigration(d.thumbTokenBucket, d.thumbConcurrency)
	}
	// Check the VideoThumbPos value
	if d.VideoThumbPos == "" {
		d.VideoThumbPos = "20%"
	}
	if strings.HasSuffix(d.VideoThumbPos, "%") {
		percentage := strings.TrimSuffix(d.VideoThumbPos, "%")
		val, err := strconv.ParseFloat(percentage, 64)
		if err != nil {
			return fmt.Errorf("invalid video_thumb_pos value: %s, err: %s", d.VideoThumbPos, err)
		}
		if val < 0 || val > 100 {
			return fmt.Errorf("invalid video_thumb_pos value: %s, the percentage must be a number between 0 and 100", d.VideoThumbPos)
		}
		d.videoThumbPosIsPercentage = true
		d.videoThumbPos = val / 100
	} else {
		val, err := strconv.ParseFloat(d.VideoThumbPos, 64)
		if err != nil {
			return fmt.Errorf("invalid video_thumb_pos value: %s, err: %s", d.VideoThumbPos, err)
		}
		if val < 0 {
			return fmt.Errorf("invalid video_thumb_pos value: %s, the time must be a positive number", d.VideoThumbPos)
		}
		d.videoThumbPosIsPercentage = false
		d.videoThumbPos = val
	}
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
		// Construct the logical path for the item
		itemPath := stdpath.Join(args.ReqPath, item.Name)

		if !item.IsDir {
			obj := &model.Object{
				ID:       item.ID,
				Name:     item.Name,
				Path:     itemPath,
				Size:     int64(item.Size),
				IsFolder: false,
				Modified: item.MTime,
			}
			// Wrap with thumbnail if enabled and file is image/video
			if d.Thumbnail {
				typeName := utils.GetFileType(item.Name)
				if typeName == conf.IMAGE || typeName == conf.VIDEO {
					thumbURL := common.GetApiUrl(ctx) + stdpath.Join("/d", itemPath)
					thumbURL = utils.EncodePath(thumbURL, true)
					thumbURL += "?type=thumb&sign=" + sign.Sign(itemPath)
					res = append(res, &model.ObjThumb{
						Object:    *obj,
						Thumbnail: model.Thumbnail{Thumbnail: thumbURL},
					})
					continue
				}
			}
			res = append(res, obj)
		} else {
			res = append(res, &model.Object{
				ID:       item.ID,
				Name:     item.Name,
				Path:     itemPath,
				Size:     0,
				IsFolder: true,
				Modified: item.MTime,
			})
		}
	}
	return res, nil
}

func (d *Ddrv) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	// Handle thumbnail requests
	if args.Type == "thumb" && d.Thumbnail {
		var buf *bytes.Buffer
		var thumbPath *string
		err := d.thumbTokenBucket.Do(ctx, func() error {
			var err error
			buf, thumbPath, err = d.getThumb(ctx, file)
			return err
		})
		if err != nil {
			return nil, err
		}
		link := &model.Link{
			Header: http.Header{
				"Content-Type": []string{"image/png"},
			},
		}
		if thumbPath != nil {
			open, err := os.Open(*thumbPath)
			if err != nil {
				return nil, err
			}
			link.MFile = open
		} else {
			link.MFile = model.NewNopMFile(bytes.NewReader(buf.Bytes()))
		}
		return link, nil
	}

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
