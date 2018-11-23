// Copyright (c) 2014-2017 Ludovic Fauvet
// Licensed under the MIT license

package http

import (
	"encoding/json"
	"fmt"
	"html/template"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	. "github.com/etix/mirrorbits/config"
	"github.com/etix/mirrorbits/core"
	"github.com/etix/mirrorbits/database"
	"github.com/etix/mirrorbits/filesystem"
	"github.com/etix/mirrorbits/logs"
	"github.com/etix/mirrorbits/mirrors"
	"github.com/etix/mirrorbits/network"
	"github.com/etix/mirrorbits/utils"
	"github.com/xbmc/mirrorbits/useragent"
	"github.com/gomodule/redigo/redis"
	"github.com/op/go-logging"
	"gopkg.in/tylerb/graceful.v1"
)

var (
	log = logging.MustGetLogger("main")
)

// HTTP represents an instance of the HTTP webserver
type HTTP struct {
	geoip          *network.GeoIP
	redis          *database.Redis
	templates      Templates
	Listener       *net.Listener
	server         *graceful.Server
	serverStopChan <-chan struct{}
	stats          *Stats
	cache          *mirrors.Cache
	engine         mirrorSelection
	Restarting     bool
	stopped        bool
	stoppedMutex   sync.Mutex
	blockedUAs     []string
	uACountOnlyS   bool
	uACountSpecial string
	parseUA        bool
}

// Templates is a struct embedding instances of the precompiled templates
type Templates struct {
	*sync.RWMutex

	mirrorlist     *template.Template
	mirrorstats    *template.Template
	downloadstats  *template.Template
	useragentstats *template.Template
}

// HTTPServer is the constructor of the HTTP server
func HTTPServer(redis *database.Redis, cache *mirrors.Cache) *HTTP {
	h := new(HTTP)
	h.redis = redis
	h.geoip = network.NewGeoIP()
	h.templates.RWMutex = new(sync.RWMutex)
	h.templates.mirrorlist = template.Must(h.LoadTemplates("mirrorlist"))
	h.templates.mirrorstats = template.Must(h.LoadTemplates("mirrorstats"))
	h.templates.downloadstats = template.Must(h.LoadTemplates("downloadstats"))
	h.templates.useragentstats = template.Must(h.LoadTemplates("useragentstats"))
	h.cache = cache
	h.stats = NewStats(redis)
	h.engine = DefaultEngine{}
	h.blockedUAs = GetConfig().UserAgentStatsConf.BlockedUserAgents
	h.uACountOnlyS = GetConfig().UserAgentStatsConf.CountOnlySpecialPath
	h.uACountSpecial = GetConfig().UserAgentStatsConf.CountSpecialPath
	h.parseUA = h.uACountOnlyS == false || len(h.blockedUAs) > 0
	http.Handle("/", NewGzipHandler(h.requestDispatcher))

	// Load the GeoIP databases
	if err := h.geoip.LoadGeoIP(); err != nil {
		if gerr, ok := err.(network.GeoIPError); ok {
			for _, e := range gerr.Errors {
				log.Critical(e.Error())
			}
			if gerr.IsFatal() {
				if len(GetConfig().Fallbacks) == 0 {
					log.Fatal("Can't load the GeoIP databases, please set a valid path in the mirrorbits configuration")
				} else {
					log.Critical("Can't load the GeoIP databases, all requests will be served by the fallback mirrors")
				}
			} else {
				log.Critical("One or more GeoIP database could not be loaded, service will run in degraded mode")
			}
		}
	}

	// Initialize the random number generator
	rand.Seed(time.Now().UnixNano())
	return h
}

// SetListener can be used to set a different listener that should be used by the
// HTTP server. This is primarily used during seamless binary upgrade.
func (h *HTTP) SetListener(l net.Listener) {
	h.Listener = &l
}

// Stop gracefully stops the HTTP server with a timeout to let
// the remaining connections finish
func (h *HTTP) Stop(timeout time.Duration) {
	/* Close the server and process remaining connections */
	h.stoppedMutex.Lock()
	defer h.stoppedMutex.Unlock()
	if h.stopped {
		return
	}
	h.stopped = true
	h.server.Stop(timeout)
}

// Terminate terminates the current HTTP server gracefully
func (h *HTTP) Terminate() {
	/* Wait for the server to stop */
	select {
	case <-h.serverStopChan:
	}
	/* Commit the latest recorded stats to the database */
	h.stats.Terminate()
}

// StopChan returns a channel that notifies when the server is stopped
func (h *HTTP) StopChan() <-chan struct{} {
	return h.serverStopChan
}

// Reload the configuration
func (h *HTTP) Reload() {
	// Reload the GeoIP database
	h.geoip.LoadGeoIP()

	// Reload the templates
	h.templates.Lock()
	if t, err := h.LoadTemplates("mirrorlist"); err == nil {
		h.templates.mirrorlist = t
	} else {
		log.Errorf("could not reload templates 'mirrorlist': %s", err.Error())
	}
	if t, err := h.LoadTemplates("mirrorstats"); err == nil {
		h.templates.mirrorstats = t
	} else {
		log.Errorf("could not reload templates 'mirrorstats': %s", err.Error())
	}
	if t, err := h.LoadTemplates("downloadstats"); err == nil {
		h.templates.downloadstats = t
	} else {
		log.Error("could not reload templates 'downloadstats': %s", err.Error())
	}
	if t, err := h.LoadTemplates("useragentstats"); err == nil {
		h.templates.useragentstats = t //XXX lock needed?
	} else {
		log.Error("could not reload templates 'useragentstats': %s", err.Error())
	}
	h.templates.Unlock()
}

// RunServer is the main function used to start the HTTP server
func (h *HTTP) RunServer() (err error) {
	// If listener isn't nil that means that we're running a seamless
	// binary upgrade and we have recovered an already running listener
	if h.Listener == nil {
		proto := "tcp"
		address := GetConfig().ListenAddress
		if strings.HasPrefix(address, "unix:") {
			proto = "unix"
			address = strings.TrimPrefix(address, "unix:")
		}
		listener, err := net.Listen(proto, address)
		if err != nil {
			log.Fatal("Listen: ", err)
		}
		h.SetListener(listener)
	}

	h.server = &graceful.Server{
		// http
		Server: &http.Server{
			Handler:        nil,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			MaxHeaderBytes: 1 << 20,
		},

		// graceful
		Timeout:          10 * time.Second,
		NoSignalHandling: true,
	}
	h.serverStopChan = h.server.StopChan()

	log.Infof("Service listening on %s", GetConfig().ListenAddress)

	/* Serve until we receive a SIGTERM */
	return h.server.Serve(*h.Listener)
}

func (h *HTTP) requestDispatcher(w http.ResponseWriter, r *http.Request) {
	h.templates.RLock()
	ctx := NewContext(w, r, h.templates)
	h.templates.RUnlock()

	w.Header().Set("Server", "Mirrorbits/"+core.VERSION)

	switch ctx.Type() {
	case MIRRORLIST:
		fallthrough
	case STANDARD:
		h.mirrorHandler(w, r, ctx)
	case MIRRORSTATS:
		h.mirrorStatsHandler(w, r, ctx)
	case FILESTATS:
		h.fileStatsHandler(w, r, ctx)
	case DOWNLOADSTATS:
		h.downloadStatsHandler(w, r, ctx)
	case USERAGENTSTATS:
		h.userAgentStatsHandler(w, r, ctx)
	case CHECKSUM:
		h.checksumHandler(w, r, ctx)
	}
}

func (h *HTTP) mirrorHandler(w http.ResponseWriter, r *http.Request, ctx *Context) {
	//XXX it would be safer to recover in case of panic

	// Sanitize path
	urlPath, err := filesystem.EvaluateFilePath(GetConfig().Repository, r.URL.Path)
	if err != nil {
		if err == filesystem.ErrOutsideRepo {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	fileInfo := filesystem.NewFileInfo(urlPath)

	remoteIP := network.ExtractRemoteIP(r.Header.Get("X-Forwarded-For"))
	if len(remoteIP) == 0 {
		remoteIP = network.RemoteIPFromAddr(r.RemoteAddr)
	}

	if ctx.IsMirrorlist() {
		fromip := ctx.QueryParam("fromip")
		if net.ParseIP(fromip) != nil {
			remoteIP = fromip
		}
	}

	// parse user agent
	uACountSpecial := false
	clientUA := useragent.UaInfo{}

	if h.parseUA {
		ua := useragent.NewUserAgent(r.UserAgent())

		// Useragent blocked?
		if len(h.blockedUAs) > 0 {
			for _, b := range h.blockedUAs {
				if strings.Trim(ua.Browser, " ") == b {
					http.NotFound(w, r)
					return
				}
			}
		}

		clientUA = useragent.UaInfo{
			Platform: strings.Trim(ua.Platform, " "),
			OS:       strings.Trim(ua.OS+" "+ua.OSVer, " "),
			Browser:  strings.Trim(ua.Browser, " "),
			Special:  uACountSpecial,
		}
	}
	if h.uACountOnlyS || len(h.uACountSpecial) > 0 {
		//for _, f := range h.uACountSpecial {
		if strings.Contains(r.URL.Path, h.uACountSpecial) {
			uACountSpecial = true
			ua2 := useragent.NewUserAgent(r.UserAgent())
			for _, b := range GetConfig().UserAgentStatsConf.BrowsersWithVersion {
				if strings.Contains(ua2.Browser, b) {
					clientUA = useragent.UaInfo{
						Platform: strings.Trim(ua2.Platform, " "),
						OS:       strings.Trim(ua2.OS+" "+ua2.OSVer, " "),
						Browser:  strings.Trim(ua2.Browser, " "),
						Special:  uACountSpecial,
					}

					// check if our special file has a newer version
					rconn := h.redis.Get()
					defer rconn.Close()

					sp, err := redis.String(rconn.Do("GET", "special_file_path"))
					if err != nil {
						log.Debug("error in redis: %s", err)
					}
					if sp < r.URL.Path {
						newfile := fmt.Sprintf("special_file_path_%s", time.Now().Format("2006_01_02"))
						rconn.Send("MULTI")
						rconn.Send("RENAME", "special_file_path", newfile)
						rconn.Send("SET", "special_file_path", r.URL.Path)

						for _, key := range []string{"platform", "os", "browser"} {
							mkey := fmt.Sprintf("STATS_SPECIAL_%s_%s", key, time.Now().Format("2006_01_02"))
							for i := 0; i < 2; i++ {
								rconn.Send("DEL", mkey)
								mkey = mkey[:strings.LastIndex(mkey, "_")]
							}
						}
						_, err := rconn.Do("EXEC")
						if err != nil {
							log.Debug("error in redis: %s", err)
						} else {
							log.Info("CountSpecialPath changed to %s", r.URL.Path)
						}
					} else if sp > r.URL.Path {
						clientUA = useragent.UaInfo{}
					}
					break
				}
			}
		}
	}

	clientInfo := h.geoip.GetRecord(remoteIP) //TODO return a pointer?

	mlist, excluded, err := h.engine.Selection(ctx, h.cache, &fileInfo, clientInfo)

	/* Handle errors */
	fallback := false
	if _, ok := err.(net.Error); ok || len(mlist) == 0 {
		/* Handle fallbacks */
		fallbacks := GetConfig().Fallbacks
		if len(fallbacks) > 0 {
			fallback = true
			for i, f := range fallbacks {
				mlist = append(mlist, mirrors.Mirror{
					ID:            i * -1,
					Name:          fmt.Sprintf("fallback%d", i),
					HttpURL:       f.URL,
					CountryCodes:  strings.ToUpper(f.CountryCode),
					CountryFields: []string{strings.ToUpper(f.CountryCode)},
					ContinentCode: strings.ToUpper(f.ContinentCode)})
			}
			sort.Sort(mirrors.ByRank{Mirrors: mlist, ClientInfo: clientInfo})
		} else {
			// No fallback in stock, there's nothing else we can do
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			log.Error("code: %d, file: %s, client: %s, mirrors: %s, useragent: %s", http.StatusServiceUnavailable, r.URL.Path, remoteIP, mlist, r.UserAgent())
			return
		}
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Error("error: %s, file: %s, client: %s, mirrors: %s, useragent: %s", err.Error(), r.URL.Path, remoteIP, mlist, r.UserAgent())
		return
	}

	results := &mirrors.Results{
		FileInfo:     fileInfo,
		MirrorList:   mlist,
		ExcludedList: excluded,
		ClientInfo:   clientInfo,
		IP:           remoteIP,
		Fallback:     fallback,
		LocalJSPath:  GetConfig().LocalJSPath,
	}

	var resultRenderer resultsRenderer

	if ctx.IsMirrorlist() {
		resultRenderer = &MirrorListRenderer{}
	} else {
		switch GetConfig().OutputMode {
		case "json":
			resultRenderer = &JSONRenderer{}
		case "redirect":
			resultRenderer = &RedirectRenderer{}
		case "auto":
			accept := r.Header.Get("Accept")
			if strings.Index(accept, "application/json") >= 0 {
				resultRenderer = &JSONRenderer{}
			} else {
				resultRenderer = &RedirectRenderer{}
			}
		default:
			http.Error(w, "No page renderer", http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Cache-Control", "private, no-cache")

	status, err := resultRenderer.Write(ctx, results)
	if err != nil {
		http.Error(w, err.Error(), status)
	}

	if !ctx.IsMirrorlist() {
		logs.LogDownload(resultRenderer.Type(), status, results, err, r.UserAgent())
		if len(mlist) > 0 {
			h.stats.CountDownload(mlist[0], fileInfo, clientUA)
		}
	}

	return
}

// LoadTemplates pre-loads templates from the configured template directory
func (h *HTTP) LoadTemplates(name string) (t *template.Template, err error) {
	t = template.New("t")
	t.Funcs(template.FuncMap{
		"add":       utils.Add,
		"sizeof":    utils.ReadableSize,
		"version":   utils.Version,
		"hostname":  utils.Hostname,
		"concaturl": utils.ConcatURL,
		"dateutc":   utils.FormattedDateUTC,
	})
	t, err = t.ParseFiles(
		filepath.Clean(GetConfig().Templates+"/base.html"),
		filepath.Clean(fmt.Sprintf("%s/%s.html", GetConfig().Templates, name)))
	if err != nil {
		if e, ok := err.(*os.PathError); ok {
			log.Fatalf(fmt.Sprintf("Cannot load template %s: %s", e.Path, e.Err.Error()))
		} else {
			log.Fatal(err.Error())
		}
	}
	return t, err
}

// StatsFileNow is the structure containing the latest stats of a file
type StatsFileNow struct {
	Today int64
	Month int64
	Year  int64
	Total int64
}

// StatsFilePeriod is the structure containing the stats for the given period
type StatsFilePeriod struct {
	Period    string
	Downloads int64
}

// See stats.go header for the storage structure
func (h *HTTP) fileStatsHandler(w http.ResponseWriter, r *http.Request, ctx *Context) {
	var output []byte

	rconn := h.redis.Get()
	defer rconn.Close()

	req := strings.SplitN(ctx.QueryParam("stats"), "-", 3)

	// Sanity check
	for _, e := range req {
		if e == "" {
			continue
		}
		if _, err := strconv.ParseInt(e, 10, 0); err != nil {
			http.Error(w, "Invalid period", http.StatusBadRequest)
			return
		}
	}

	if len(req) == 0 || req[0] == "" {
		fkey := fmt.Sprintf("STATS_FILE_%s", time.Now().Format("2006_01_02"))

		rconn.Send("MULTI")

		for i := 0; i < 4; i++ {
			rconn.Send("HGET", fkey, r.URL.Path)
			fkey = fkey[:strings.LastIndex(fkey, "_")]
		}

		res, err := redis.Values(rconn.Do("EXEC"))

		if err != nil && err != redis.ErrNil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		s := &StatsFileNow{}
		s.Today, _ = redis.Int64(res[0], err)
		s.Month, _ = redis.Int64(res[1], err)
		s.Year, _ = redis.Int64(res[2], err)
		s.Total, _ = redis.Int64(res[3], err)

		output, err = json.MarshalIndent(s, "", "    ")
	} else {
		// Generate the redis key
		dkey := "STATS_FILE_"
		for _, e := range req {
			dkey += fmt.Sprintf("%s_", e)
		}
		dkey = dkey[:len(dkey)-1]

		v, err := redis.Int64(rconn.Do("HGET", dkey, r.URL.Path))
		if err != nil && err != redis.ErrNil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		s := &StatsFilePeriod{Period: ctx.QueryParam("stats"), Downloads: v}

		output, err = json.MarshalIndent(s, "", "    ")
	}

	ctx.ResponseWriter().Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write(output)
}

type DownloadStats struct {
	Filename  string
	Downloads int64
}

type DownloadStatsPage struct {
	List   []*DownloadStats
	Period string
	Limit  int
	Month  string
	Today  string
	Path   string
	LocalJSPath string
}

func (h *HTTP) downloadStatsHandler(w http.ResponseWriter, r *http.Request, ctx *Context) {
	var results []*DownloadStats
	var output []byte
	var filter string
	var period string
	var index int64

	// parse query params
	req := strings.SplitN(ctx.QueryParam("downloadstats"), "-", 3)
	if req[0] != "" {
		for _, e := range req {
			if _, err := strconv.ParseInt(e, 10, 0); err != nil {
				http.Error(w, "Invalid period", http.StatusBadRequest)
				return
			}
		}
		period = strings.Replace(ctx.QueryParam("downloadstats"), "-", "_", 3)
	}

	format := "text"
	if ctx.QueryParam("format") == "json" {
		format = "json"
	}

	haveFilter := false
	if len(ctx.QueryParam("filter")) >= 1 {
		haveFilter = true
		filter = strings.Trim(ctx.QueryParam("filter"), " !#&%$*+'")
	}

	limit := 100
	haveLimit := true
	if ctx.QueryParam("limit") != "" {
		l, err := strconv.ParseInt(ctx.QueryParam("limit"), 0, 0)
		if err != nil || l < 0 {
			http.Error(w, "Invalid limit", http.StatusBadRequest)
			return
		}
		limit = int(l)
		if limit == 0 {
			haveLimit = false
		}
	}

	t0 := time.Now()
	rconn := h.redis.Get()
	defer rconn.Close()

	// get stats array from redis
	var dkey string
	if len(period) >= 4 {
		dkey = fmt.Sprintf("STATS_FILE_%s", period)
	} else {
		dkey = "STATS_FILE"
	}
	v, err := redis.Strings(rconn.Do("HGETALL", dkey))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// generatate a map of our results, with download count as index
	var m = make(map[int64]string)
	for i := 0; i < len(v); i = i + 2 {
		index, _ = strconv.ParseInt(v[i+1], 10, 64)
		if haveFilter {
			if strings.Contains(v[i], filter) {
				m[index] = v[i]
			}
		} else {
			m[index] = v[i]
		}
	}
	v = nil

	// generate a sortable int64 array of our map indices
	dls := make([]int64, len(m))
	var i int64 = 0
	for k := range m {
		dls[i] = k
		i++
	}

	// sort the array in reverse order
	utils.Int64Slice.Reverse(dls)
	log.Debug("Stats generation took %v", time.Now().Sub(t0))

	// construct final results
	t4 := time.Now()
	stop := 0
	for _, k := range dls {
		s := &DownloadStats{Downloads: k, Filename: m[k]}
		results = append(results, s)

		if haveLimit {
			stop++
			if stop >= limit {
				break
			}
		}
	}

	// output
	if format == "text" {
		if len(period) < 4 {
			period = "All time"
		}
		today := time.Now().Format("2006-01-02")
		month := time.Now().Format("2006-01")

		err = ctx.Templates().downloadstats.ExecuteTemplate(ctx.ResponseWriter(), "base",
			DownloadStatsPage{results, period, limit, month, today, GetConfig().DownloadStatsPath, GetConfig().LocalJSPath})
		if err != nil {
			log.Error("Error rendering downloadstats: %s", err.Error())
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
	} else {
		output, err = json.MarshalIndent(results, "", "    ")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		ctx.ResponseWriter().Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(output)
	}
	log.Debug("downloadStatsHandler: output took %v", time.Now().Sub(t4))

}

type UserAgentStats struct {
	Name      string
	Downloads int64
}

type UserAgentStatsPage struct {
	List   []*UserAgentStats
	Type   string
	Period string
	Limit  int
	Month  string
	Today  string
	Path   string
	LocalJSPath string
}

func (h *HTTP) userAgentStatsHandler(w http.ResponseWriter, r *http.Request, ctx *Context) {
	var results []*UserAgentStats
	var output []byte
	var filter string
	var period string

	// parse query params
	req := strings.SplitN(ctx.QueryParam("useragentstats"), "-", 3)
	if req[0] != "" {
		for _, e := range req {
			if _, err := strconv.ParseInt(e, 10, 0); err != nil {
				http.Error(w, "Invalid period", http.StatusBadRequest)
				return
			}
		}
		period = strings.Replace(ctx.QueryParam("useragentstats"), "-", "_", 3)
	}

	item := "os"
	if len(ctx.QueryParam("type")) >= 1 {
		item = ctx.QueryParam("type")
	}

	format := "text"
	if ctx.QueryParam("format") == "json" {
		format = "json"
	}

	haveFilter := false
	if len(ctx.QueryParam("filter")) >= 1 {
		haveFilter = true
		filter = strings.Trim(ctx.QueryParam("filter"), " !#&%$*+'")
	}

	limit := 100
	if ctx.QueryParam("limit") != "" {
		l, err := strconv.ParseInt(ctx.QueryParam("limit"), 0, 0)
		if err != nil || l < 0 {
			http.Error(w, "Invalid limit", http.StatusBadRequest)
			return
		}
		limit = int(l)
	}

	name := "USERAGENT"
	if len(ctx.QueryParam("special")) > 0 {
		name = "SPECIAL"
	}

	t0 := time.Now()
	rconn := h.redis.Get()
	defer rconn.Close()

	// get stats array from redis
	var dkey string
	if len(period) >= 4 {
		dkey = fmt.Sprintf("STATS_%s_%s_%s", name, item, period)
	} else {
		dkey = fmt.Sprintf("STATS_%s_%s", name, item)
	}
	v, err := redis.Strings(rconn.Do("ZREVRANGE", dkey, "0", limit-1, "withscores"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// generatate results
	for i := 0; i < len(v); i = i + 2 {
		dls, _ := strconv.ParseInt(v[i+1], 10, 64)
		if haveFilter {
			if strings.Contains(v[i], filter) {
				s := &UserAgentStats{Downloads: dls, Name: v[i]}
				results = append(results, s)
			}
		} else {
			s := &UserAgentStats{Downloads: dls, Name: v[i]}
			results = append(results, s)
		}
	}

	log.Debug("Stats generation took %v", time.Now().Sub(t0))
	t1 := time.Now()

	// output
	if format == "text" {
		if len(period) < 4 {
			period = "All time"
		}
		today := time.Now().Format("2006-01-02")
		month := time.Now().Format("2006-01")

		err = ctx.Templates().useragentstats.ExecuteTemplate(ctx.ResponseWriter(), "base",
			UserAgentStatsPage{results, item, period, limit, month, today, GetConfig().DownloadStatsPath, GetConfig().LocalJSPath})
		if err != nil {
			log.Error("Error rendering useragentstats: %s", err.Error())
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
	} else {
		output, err = json.MarshalIndent(results, "", "    ")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
			return
		}
		ctx.ResponseWriter().Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write(output)
	}
	log.Debug("userAgentStatsHandler: output took %v", time.Now().Sub(t1))

}

func (h *HTTP) checksumHandler(w http.ResponseWriter, r *http.Request, ctx *Context) {

	// Sanitize path
	urlPath, err := filesystem.EvaluateFilePath(GetConfig().Repository, r.URL.Path)
	if err != nil {
		if err == filesystem.ErrOutsideRepo {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		return
	}

	fileInfo, err := h.cache.GetFileInfo(urlPath)
	if err == redis.ErrNil {
		http.NotFound(w, r)
		return
	} else if err != nil {
		log.Errorf("Error while fetching Fileinfo: %s", err.Error())
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}

	var hash string

	if ctx.paramBool("md5") {
		hash = fileInfo.Md5
	} else if ctx.paramBool("sha1") {
		hash = fileInfo.Sha1
	} else if ctx.paramBool("sha256") {
		hash = fileInfo.Sha256
	}

	if len(hash) == 0 {
		http.Error(w, "Hash type not supported", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.Write([]byte(fmt.Sprintf("%s  %s", hash, filepath.Base(fileInfo.Path))))

	return
}

// MirrorStats contains the stats of a given mirror
type MirrorStats struct {
	ID         int
	Name       string
	Downloads  int64
	Bytes      int64
	PercentD   float32
	PercentB   float32
	SyncOffset SyncOffset
}

// SyncOffset contains the time offset between the mirror and the local repository
type SyncOffset struct {
	Valid         bool
	Value         int // in hours
	HumanReadable string
}

// MirrorStatsPage contains the values needed to generate the mirrorstats page
type MirrorStatsPage struct {
	List        []MirrorStats
	MirrorList  []mirrors.Mirror
	LocalJSPath string
}

// byDownloadNumbers is a sorting function
type byDownloadNumbers struct {
	mirrorStatsSlice
}

func (b byDownloadNumbers) Less(i, j int) bool {
	if b.mirrorStatsSlice[i].Downloads > b.mirrorStatsSlice[j].Downloads {
		return true
	}
	return false
}

// mirrorStatsSlice is a slice of MirrorStats
type mirrorStatsSlice []MirrorStats

func (s mirrorStatsSlice) Len() int      { return len(s) }
func (s mirrorStatsSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (h *HTTP) mirrorStatsHandler(w http.ResponseWriter, r *http.Request, ctx *Context) {

	rconn := h.redis.Get()
	defer rconn.Close()

	// Get all mirrors ID
	mirrorsMap, err := h.redis.GetListOfMirrors()
	if err != nil {
		http.Error(w, "Cannot fetch the list of mirrors", http.StatusInternalServerError)
		return
	}

	var mirrorsIDs []int
	for id := range mirrorsMap {
		// We need a common order to iterate the
		// results from Redis.
		mirrorsIDs = append(mirrorsIDs, id)
	}

	rconn.Send("MULTI")

	// Get all mirrors stats
	for _, id := range mirrorsIDs {
		today := time.Now().UTC().Format("2006_01_02")
		rconn.Send("HGET", "STATS_MIRROR_"+today, id)
		rconn.Send("HGET", "STATS_MIRROR_BYTES_"+today, id)
	}

	stats, err := redis.Values(rconn.Do("EXEC"))
	if err != nil {
		http.Error(w, "Cannot fetch stats", http.StatusInternalServerError)
		return
	}

	var maxdownloads int64
	var maxbytes int64
	var results []MirrorStats
	var index int64
	mlist := make([]mirrors.Mirror, 0, len(mirrorsIDs))
	for _, id := range mirrorsIDs {
		mirror, err := h.cache.GetMirror(id)
		if err != nil {
			continue
		}
		mlist = append(mlist, mirror)

		var downloads int64
		if v, _ := redis.String(stats[index], nil); v != "" {
			downloads, _ = strconv.ParseInt(v, 10, 64)
		}
		var bytes int64
		if v, _ := redis.String(stats[index+1], nil); v != "" {
			bytes, _ = strconv.ParseInt(v, 10, 64)
		}

		if downloads > maxdownloads {
			maxdownloads = downloads
		}
		if bytes > maxbytes {
			maxbytes = bytes
		}

		var lastModTime time.Time

		if !mirror.LastModTime.IsZero() {
			lastModTime = mirror.LastModTime.Time
		}

		elapsed := time.Since(lastModTime)

		s := MirrorStats{
			ID:        id,
			Name:      mirror.Name,
			Downloads: downloads,
			Bytes:     bytes,
			SyncOffset: SyncOffset{
				Valid:         !lastModTime.IsZero(),
				Value:         int(elapsed.Hours()),
				HumanReadable: utils.FuzzyTimeStr(elapsed),
			},
		}
		results = append(results, s)
		index += 2
	}

	sort.Sort(byDownloadNumbers{results})

	for i := 0; i < len(results); i++ {
		results[i].PercentD = float32(results[i].Downloads) * 100 / float32(maxdownloads)
		results[i].PercentB = float32(results[i].Bytes) * 100 / float32(maxbytes)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	err = ctx.Templates().mirrorstats.ExecuteTemplate(w, "base", MirrorStatsPage{results, mlist, GetConfig().LocalJSPath})
	if err != nil {
		log.Errorf("HTTP error: %s", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}
