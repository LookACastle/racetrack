package main

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/inconshreveable/log15"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
)

func proxyEndpoint(c *gin.Context, cfg *Config) {
	startTime := time.Now()

	requestId := getRequestTracingId(c.Request, cfg.RequestTracingHeader)
	logger := log.New(log.Ctx{
		"requestId": requestId,
	})

	logger.Info("Incoming Proxy request", log.Ctx{"method": c.Request.Method, "path": c.Request.URL.Path})
	statusCode, err := handleProxyRequest(c, cfg, logger, requestId)
	if err != nil {
		metricJobProxyRequestErrors.Inc()
		errorStr := err.Error()
		logger.Error("Proxy request error", log.Ctx{
			"status": statusCode,
			"error":  errorStr,
			"path":   c.Request.URL.Path,
		})
		http.Error(c.Writer, errorStr, statusCode)
	}
	metricOverallJobProxyResponseTime.Add(time.Since(startTime).Seconds())
}

func handleProxyRequest(
	c *gin.Context,
	cfg *Config,
	logger log.Logger,
	requestId string,
) (int, error) {

	if c.Request.Method != "POST" && c.Request.Method != "GET" {
		c.Writer.Header().Set("Allow", "GET, POST")
		return http.StatusMethodNotAllowed, errors.New("Method not allowed")
	}

	jobName := c.Param("job")
	if jobName == "" {
		return http.StatusBadRequest, errors.New("Couldn't extract job name")
	}

	jobVersion := c.Param("version")
	if jobVersion == "" {
		return http.StatusBadRequest, errors.New("Couldn't extract job version")
	}

	if c.Request.Header.Get("Accept") == "" {
		return http.StatusBadRequest, errors.New("Missing 'Accept' header. " +
			"You might wanted to include 'Accept: application/json, */*' request header.")
	}

	jobPath := c.Param("path")

	authToken := getAuthFromHeaderOrCookie(c.Request)
	lifecycleClient := NewLifecycleClient(cfg.LifecycleUrl, authToken,
		cfg.LifecycleToken, cfg.RequestTracingHeader, requestId)

	job, err := lifecycleClient.GetJobDetails(jobName, jobVersion)
	if err != nil {
		if errors.Is(err, JobNotFound) {
			return http.StatusNotFound, err
		}
		return http.StatusInternalServerError, errors.Wrap(err, "failed to get Job details")
	}

	metricJobProxyRequests.WithLabelValues(jobName, job.Version).Inc()

	if cfg.AuthRequired {
		err := lifecycleClient.AuthenticateCaller(c.Request.URL.Path, jobName, job.Version, jobPath, cfg.AuthDebug)
		if err == nil {
			metricAuthSuccessful.Inc()
		} else {
			metricAuthFailed.Inc()
			if errors.As(err, &AuthenticationFailure{}) {
				return http.StatusUnauthorized, errors.Wrap(err, "Unauthenticated")
			}
			return http.StatusInternalServerError, errors.Wrap(err, "Checking authentication error")
		}
	}

	targetUrl := TargetURL(cfg, job, c.Request.URL.Path)
	ServeReverseProxy(targetUrl, c.Writer, c.Request, jobName, job.Version, cfg, logger, requestId)
	return 200, nil
}

func ServeReverseProxy(
	target url.URL,
	res http.ResponseWriter,
	pubReq *http.Request,
	jobName, jobVersion string,
	cfg *Config,
	logger log.Logger,
	requestId string,
) {

	director := func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = target.Path
		req.Host = pubReq.Host
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Set(cfg.RequestTracingHeader, requestId)
		req.RequestURI = ""
	}

	modifyResponse := func(res *http.Response) error {
		// Transform redirect links to relative (without hostname).
		// Target server doesn't know it's being proxied so it tries to redirect to internal URL.
		location := res.Header.Get("Location")
		if location != "" {
			redirectUrl, err := url.Parse(location)
			if err == nil {
				redirectUrl.Host = ""
				redirectUrl.Scheme = ""
				res.Header.Set("Location", redirectUrl.String())
			}
		}

		res.Header.Set(cfg.RequestTracingHeader, requestId)
		logger.Info("Proxy request done", log.Ctx{
			"jobName":    jobName,
			"jobVersion": jobVersion,
			"jobPath":    target.Path,
			"status":        res.StatusCode,
		})
		statusCode := strconv.Itoa(res.StatusCode)
		metricJobProxyResponseCodes.WithLabelValues(jobName, jobVersion, statusCode).Inc()
		return nil
	}

	errorHandler := func(res http.ResponseWriter, req *http.Request, err error) {
		logger.Error("Reverse proxy error", log.Ctx{
			"jobName":    jobName,
			"jobVersion": jobVersion,
			"host":          target.Host,
			"path":          target.Path,
			"error":         err.Error(),
		})
		metricJobProxyErrors.Inc()
	}

	proxy := &httputil.ReverseProxy{
		Director:       director,
		ModifyResponse: modifyResponse,
		ErrorHandler:   errorHandler,
	}

	metricJobProxyRequestsStarted.WithLabelValues(jobName, jobVersion).Inc()
	jobCallStartTime := time.Now()

	proxy.ServeHTTP(res, pubReq)

	jobCallTime := time.Since(jobCallStartTime).Seconds()
	metricJobCallResponseTimeHistogram.WithLabelValues(jobName, jobVersion).Observe(jobCallTime)
	metricJobCallResponseTime.WithLabelValues(jobName, jobVersion).Add(jobCallTime)
	metricJobProxyRequestsDone.WithLabelValues(jobName, jobVersion).Inc()
}

func getRequestTracingId(req *http.Request, headerName string) string {
	tracingId := req.Header.Get(headerName)
	if tracingId != "" {
		return tracingId
	}
	return uuid.NewV4().String()
}
