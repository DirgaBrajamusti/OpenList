package ddrv

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// do others that not defined in Driver interface
func mbody(reader io.Reader, filename string) (string, io.Reader) {
	boundary := "disgosucks"
	contentType := fmt.Sprintf("multipart/form-data; boundary=%s", boundary)

	CRLF := "\r\n"
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
