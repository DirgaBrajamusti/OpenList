package ddrv

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/disintegration/imaging"
	ffmpeg "github.com/u2takey/ffmpeg-go"
)

// do others that not defined in Driver interface
func mbody(reader io.Reader, filename string) (string, io.Reader) {
	boundary := "disgosucks"
	// Set the content type including the boundary
	contentType := fmt.Sprintf("multipart/form-data; boundary=%s", boundary)

	CRLF := "\r\n"
	// fname := uuid.New().String()

	// Assemble all the parts of the multipart form-data
	// This includes the boundary, content disposition with the file name, content type,
	// a blank line to end headers, the actual content (reader), end of content,
	// and end of multipart data
	parts := []io.Reader{
		strings.NewReader("--" + boundary + CRLF),
		strings.NewReader(fmt.Sprintf(`Content-Disposition: form-data; name="file"; filename="%s"`, filename) + CRLF),
		strings.NewReader(fmt.Sprintf(`Content-Type: %s`, "application/octet-stream") + CRLF),
		strings.NewReader(CRLF),
		reader,
		strings.NewReader(CRLF),
		strings.NewReader("--" + boundary + "--" + CRLF),
	}

	// Return the content type and the combined reader of all parts
	return contentType, io.MultiReader(parts...)
}

func GenerateCloudflareWorkersSignedURL(baseURL, secret string, expiryInSeconds int64) (string, error) {
	expiryTimestamp := time.Now().Unix() + expiryInSeconds
	dataToSign := fmt.Sprintf("%s%d", baseURL, expiryTimestamp)

	// Generate HMAC signature
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(dataToSign))
	signature := hex.EncodeToString(h.Sum(nil))

	// Append the expiry and signature as URL parameters
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	query := parsedURL.Query()
	query.Set("expiry", strconv.FormatInt(expiryTimestamp, 10))
	query.Set("signature", signature)
	parsedURL.RawQuery = query.Encode()

	return parsedURL.String(), nil
}

// GetSnapshot extracts a video frame at the specified position
func (d *Ddrv) GetSnapshot(videoURL string) (imgData *bytes.Buffer, err error) {
	// Run ffprobe to get the video duration
	jsonOutput, err := ffmpeg.Probe(videoURL)
	if err != nil {
		return nil, err
	}
	// get format.duration from the json string
	type probeFormat struct {
		Duration string `json:"duration"`
	}
	type probeData struct {
		Format probeFormat `json:"format"`
	}
	var probe probeData
	err = json.Unmarshal([]byte(jsonOutput), &probe)
	if err != nil {
		return nil, err
	}
	totalDuration, err := strconv.ParseFloat(probe.Format.Duration, 64)
	if err != nil {
		return nil, err
	}

	var ss string
	if d.videoThumbPosIsPercentage {
		ss = fmt.Sprintf("%f", totalDuration*d.videoThumbPos)
	} else {
		// If the value is greater than the total duration, use the total duration
		if d.videoThumbPos > totalDuration {
			ss = fmt.Sprintf("%f", totalDuration)
		} else {
			ss = fmt.Sprintf("%f", d.videoThumbPos)
		}
	}

	// Run ffmpeg to get the snapshot
	srcBuf := bytes.NewBuffer(nil)
	// If the remaining time from the seek point to the end of the video is less
	// than the duration of a single frame, ffmpeg cannot extract any frames
	// within the specified range and will exit with an error.
	// The "noaccurate_seek" option prevents this error and would also speed up
	// the seek process.
	stream := ffmpeg.Input(videoURL, ffmpeg.KwArgs{"ss": ss, "noaccurate_seek": ""}).
		Output("pipe:", ffmpeg.KwArgs{"vframes": 1, "format": "image2", "vcodec": "mjpeg"}).
		GlobalArgs("-loglevel", "error").Silent(true).
		WithOutput(srcBuf, os.Stdout)
	if err = stream.Run(); err != nil {
		return nil, err
	}
	return srcBuf, nil
}

// getThumb generates a thumbnail for the given file
func (d *Ddrv) getThumb(ctx context.Context, file model.Obj) (*bytes.Buffer, *string, error) {
	thumbPrefix := "openlist_thumb_"
	thumbName := thumbPrefix + utils.GetMD5EncodeStr(file.GetID()) + ".png"

	// Check cache first
	if d.ThumbCacheFolder != "" {
		thumbPath := filepath.Join(d.ThumbCacheFolder, thumbName)
		if utils.Exists(thumbPath) {
			return nil, &thumbPath, nil
		}
	}

	// Get the download URL for the file
	var downloadURL string
	if strings.Contains(d.Addition.Address, ",") {
		urlList := strings.Split(d.Addition.Address, ",")
		randomIndex := rand.Intn(len(urlList))
		downloadURL = urlList[randomIndex] + "/files/" + file.GetID()
	} else {
		downloadURL = d.Addition.Address + "/files/" + file.GetID()
	}

	var srcBuf *bytes.Buffer
	if utils.GetFileType(file.GetName()) == conf.VIDEO {
		// For videos, use ffmpeg with HTTP URL (Approach B)
		videoBuf, err := d.GetSnapshot(downloadURL)
		if err != nil {
			return nil, nil, err
		}
		srcBuf = videoBuf
	} else {
		// For images, download the file
		client := &http.Client{}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
		if err != nil {
			return nil, nil, err
		}
		req.Header.Add("Authorization", "Bearer "+d.Addition.Token)

		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, nil, fmt.Errorf("failed to download file: %s", resp.Status)
		}

		imgData, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, err
		}
		srcBuf = bytes.NewBuffer(imgData)
	}

	image, err := imaging.Decode(srcBuf, imaging.AutoOrientation(true))
	if err != nil {
		return nil, nil, err
	}
	thumbImg := imaging.Resize(image, 144, 0, imaging.Lanczos)
	var buf bytes.Buffer
	err = imaging.Encode(&buf, thumbImg, imaging.PNG)
	if err != nil {
		return nil, nil, err
	}

	// Cache the thumbnail if cache folder is set
	if d.ThumbCacheFolder != "" {
		thumbPath := filepath.Join(d.ThumbCacheFolder, thumbName)
		err = os.WriteFile(thumbPath, buf.Bytes(), 0666)
		if err != nil {
			return nil, nil, err
		}
	}

	return &buf, nil, nil
}
