// Copyright (c) 2014-2017 Ludovic Fauvet
// Licensed under the MIT license

package http

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	. "github.com/xbmc/mirrorbits/config"
	"github.com/xbmc/mirrorbits/mirrors"
)

var (
	// ErrTemplatesNotFound is returned cannot be loaded
	ErrTemplatesNotFound = errors.New("please set a valid path to the templates directory")
)

// resultsRenderer is the interface for all result renderers
type resultsRenderer interface {
	Write(ctx *Context, results *mirrors.Results) (int, error)
	Type() string
}

// JSONRenderer is used to render JSON formatted details about the current request
type JSONRenderer struct{}

// Type returns the type of renderer
func (w *JSONRenderer) Type() string {
	return "JSON"
}

// Write is used to write the result to the ResponseWriter
func (w *JSONRenderer) Write(ctx *Context, results *mirrors.Results) (statusCode int, err error) {

	if ctx.IsPretty() {
		output, err := json.MarshalIndent(results, "", "    ")
		if err != nil {
			return http.StatusInternalServerError, err
		}

		ctx.ResponseWriter().Header().Set("Content-Type", "application/json; charset=utf-8")
		ctx.ResponseWriter().Header().Set("Content-Length", strconv.Itoa(len(output)))
		ctx.ResponseWriter().Write(output)
	} else {
		ctx.ResponseWriter().Header().Set("Content-Type", "application/json; charset=utf-8")
		err = json.NewEncoder(ctx.ResponseWriter()).Encode(results)
		if err != nil {
			return http.StatusInternalServerError, err
		}
	}

	return http.StatusOK, nil
}

// RedirectRenderer is a basic renderer that redirects the user to the first mirror in the list
type RedirectRenderer struct{}

// Type returns the type of renderer
func (w *RedirectRenderer) Type() string {
	return "REDIRECT"
}

// Write is used to write the result to the ResponseWriter
func (w *RedirectRenderer) Write(ctx *Context, results *mirrors.Results) (statusCode int, err error) {
	if len(results.MirrorList) > 0 {
		ctx.ResponseWriter().Header().Set("Content-Type", "text/html; charset=utf-8")

		path := strings.TrimPrefix(results.FileInfo.Path, "/")

		mh := len(results.MirrorList)
		maxheaders := GetConfig().MaxLinkHeaders
		if mh > maxheaders+1 {
			mh = maxheaders + 1
		}

		if mh >= 1 {
			// Generate the header alternative links
			for i, m := range results.MirrorList[1:mh] {
				var countryCode string
				if len(m.CountryFields) > 0 {
					countryCode = strings.ToLower(m.CountryFields[0])
				}
				ctx.ResponseWriter().Header().Add("Link", fmt.Sprintf("<%s>; rel=duplicate; pri=%d; geo=%s", m.HttpURL+path, i+1, countryCode))
			}
		}

		// Generate checksum headers
		if GetConfig().CheckSumHeaders {
			if len(results.FileInfo.Md5) > 0 {
				md5, _ := hex.DecodeString(results.FileInfo.Md5)
				ctx.ResponseWriter().Header().Add("Content-MD5", fmt.Sprintf("%s", base64.StdEncoding.EncodeToString(md5)))
			}
			if len(results.FileInfo.Sha1) > 0 {
				sha1, _ := hex.DecodeString(results.FileInfo.Sha1)
				ctx.ResponseWriter().Header().Add("Content-SHA1", fmt.Sprintf("%s", base64.StdEncoding.EncodeToString(sha1)))
			}
			if len(results.FileInfo.Sha256) > 0 {
				sha256, _ := hex.DecodeString(results.FileInfo.Sha256)
				ctx.ResponseWriter().Header().Add("Content-SHA256", fmt.Sprintf("%s", base64.StdEncoding.EncodeToString(sha256)))
			}
		}

		// Finally issue the redirect
		http.Redirect(ctx.ResponseWriter(), ctx.Request(), results.MirrorList[0].HttpURL+path, http.StatusFound)
		return http.StatusFound, nil
	}
	// No mirror returned for this request
	http.NotFound(ctx.ResponseWriter(), ctx.Request())
	return http.StatusNotFound, nil
}

// MirrorListRenderer is used to render the mirrorlist page using the HTML templates
type MirrorListRenderer struct{}

// Type returns the type of renderer
func (w *MirrorListRenderer) Type() string {
	return "MIRRORLIST"
}

// Write is used to write the result to the ResponseWriter
func (w *MirrorListRenderer) Write(ctx *Context, results *mirrors.Results) (statusCode int, err error) {
	if ctx.Templates().mirrorlist == nil {
		// No templates found for the mirrorlist
		return http.StatusInternalServerError, ErrTemplatesNotFound
	}
	// Sort the exclude reasons by message so they appear grouped
	sort.Sort(mirrors.ByExcludeReason{Mirrors: results.ExcludedList})

	// Create a temporary output buffer to render the page
	var buf bytes.Buffer

	ctx.ResponseWriter().Header().Set("Content-Type", "text/html; charset=utf-8")

	// Render the page into the buffer
	err = ctx.Templates().mirrorlist.ExecuteTemplate(&buf, "base", results)
	if err != nil {
		// Something went wrong, discard the buffer
		return http.StatusInternalServerError, err
	}

	// Write the buffer to the socket
	buf.WriteTo(ctx.ResponseWriter())
	return http.StatusOK, nil
}
