/*
Copyright 2020 The SuperEdge Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/munnerz/goautoneg"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	discoveryv1beta1 "k8s.io/api/discovery/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer/streaming"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"

	"github.com/superedge/superedge/pkg/lite-apiserver/cache"
	"github.com/superedge/superedge/pkg/lite-apiserver/constant"
	"github.com/superedge/superedge/pkg/lite-apiserver/transport"
	jsonserializer "k8s.io/apimachinery/pkg/runtime/serializer/json"
	apirequest "k8s.io/apiserver/pkg/endpoints/request"
	restclientwatch "k8s.io/client-go/rest/watch"
)

type WatchEvent struct {
	Type   watch.EventType `json:"type"`
	Object runtime.Object  `json:"object"`
}

// EdgeReverseProxy represents a real pair of http request and response
type EdgeReverseProxy struct {
	backendProxy *httputil.ReverseProxy

	backendUrl  string
	backendPort int

	transport    *transport.EdgeTransport
	cacheManager *cache.CacheManager

	// the address list of lite-apiserver listen
	listenAddress              string
	port                       int
	incluster                  bool
	disableLoadBalancerIngress bool
}

func NewEdgeReverseProxy(transport *transport.EdgeTransport, backendUrl string, backendPort int, cacheManager *cache.CacheManager, listenAddress string, port int, incluster, disableLoadBalancerIngress bool) *EdgeReverseProxy {
	p := &EdgeReverseProxy{
		backendPort:                backendPort,
		backendUrl:                 backendUrl,
		transport:                  transport,
		cacheManager:               cacheManager,
		listenAddress:              listenAddress,
		port:                       port,
		incluster:                  incluster,
		disableLoadBalancerIngress: disableLoadBalancerIngress,
	}

	reverseProxy := &httputil.ReverseProxy{
		Director:       p.makeDirector,
		Transport:      p.transport,
		ModifyResponse: p.modifyResponse,
		ErrorHandler:   p.handlerError,
	}

	reverseProxy.FlushInterval = -1

	p.backendProxy = reverseProxy
	return p
}

func (p *EdgeReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	klog.V(2).Infof("New request: method->%s, url->%s", r.Method, r.URL.String())

	// handle http
	p.backendProxy.ServeHTTP(w, r)
}

func (p *EdgeReverseProxy) makeDirector(req *http.Request) {
	req.URL.Scheme = "https"
	req.URL.Host = fmt.Sprintf("%s:%d", p.backendUrl, p.backendPort)
	if req.Method == http.MethodPost && strings.HasPrefix(req.URL.Path, "/api/v1/namespaces") && strings.Contains(req.URL.Path, "serviceaccounts") {
		data, err := ioutil.ReadAll(req.Body)
		if err != nil {
			klog.Errorf("Failed to read Request.Body, error: %v", err)
			return
		}
		req.Body = ioutil.NopCloser(bytes.NewBuffer(data))
		*req = *req.WithContext(context.WithValue(req.Context(), "TokenRequestData", data))
	}
}

func (p *EdgeReverseProxy) modifyResponse(resp *http.Response) error {
	if resp == nil || resp.Request == nil {
		klog.Infof("no response or request, skip cache response")
		return nil
	}

	isNeedCache := needCache(resp.Request)
	if !isNeedCache {
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		klog.V(4).Infof("resp status is %d, skip cache response", resp.StatusCode)
		return nil
	}

	// validate watch Content-Type
	info, ok := apirequest.RequestInfoFrom(resp.Request.Context())
	if !ok {
		return nil
	}
	if info.Verb == constant.VerbWatch {
		contentType := resp.Header.Get(constant.ContentType)
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			klog.Warningf("Content-Type %s is not recognized: %v", contentType, err)
			return nil
		}
		klog.V(8).Infof("mediaType is %s", mediaType)
		if mediaType != constant.Json && mediaType != constant.Yaml {
			return nil
		}
	}

	if err := p.interceptResponse(info, resp); err != nil {
		klog.Errorf("interceptResponse %v %s error: %v", info, resp.Header.Get("Content-Encoding"), err)
	}

	// cache response data
	multiRead := MultiWrite(resp.Body, 2)
	if multiRead == nil {
		return fmt.Errorf("The number of Reads specified by MultiWrite is less than 2")
	}
	go func(req *http.Request, header http.Header, statusCode int, pipeReader io.ReadCloser) {
		err := p.writeCache(req, header, statusCode, pipeReader)
		if (err != nil) && (err != io.EOF) && (err != context.Canceled) {
			klog.Errorf("Write cache error: %v", err)
		}
	}(resp.Request, resp.Header.Clone(), resp.StatusCode, multiRead[1])

	resp.Body = multiRead[0]

	return nil
}

func (p *EdgeReverseProxy) modifyKubernetesV1EndpointSlice(ep *discoveryv1.EndpointSlice) {
	if ep.ObjectMeta.Name == "kubernetes" && ep.ObjectMeta.Namespace == "default" {
		var ip string
		var port int32
		if p.incluster {
			ip = p.listenAddress
			port = int32(p.port)
		} else {
			ip = p.backendUrl
			port = int32(p.backendPort)
			ips, err := net.LookupHost(p.backendUrl)
			if err == nil && len(ips) > 0 {
				ip = ips[0]
			}
		}
		if len(ep.Endpoints) > 0 {
			ep.Endpoints[0].Addresses = []string{ip}
			ep.Ports[0].Port = &port
		}
	}
}

func (p *EdgeReverseProxy) modifyKubernetesV1Beta1EndpointSlice(ep *discoveryv1beta1.EndpointSlice) {
	if ep.ObjectMeta.Name == "kubernetes" && ep.ObjectMeta.Namespace == "default" {
		var ip string
		var port int32
		if p.incluster {
			ip = p.listenAddress
			port = int32(p.port)
		} else {
			ip = p.backendUrl
			port = int32(p.backendPort)
			ips, err := net.LookupHost(p.backendUrl)
			if err == nil && len(ips) > 0 {
				ip = ips[0]
			}
		}
		if len(ep.Endpoints) > 0 {
			ep.Endpoints[0].Addresses = []string{ip}
			ep.Ports[0].Port = &port
		}
	}
}

func getWatchDecoder(body io.ReadCloser) *restclientwatch.Decoder {
	framer := jsonserializer.Framer.NewFrameReader(body)
	jsonSerializer := jsonserializer.NewSerializerWithOptions(jsonserializer.DefaultMetaFactory, scheme.Scheme, scheme.Scheme, jsonserializer.SerializerOptions{Yaml: false, Pretty: false, Strict: false})
	streamingDecoder := streaming.NewDecoder(framer, jsonSerializer)
	return restclientwatch.NewDecoder(streamingDecoder, unstructured.UnstructuredJSONScheme)
}

func (p *EdgeReverseProxy) interceptWatchResponse(info *apirequest.RequestInfo, resp *http.Response) error {
	if info.Verb != constant.VerbWatch {
		return nil
	}

	if strings.HasPrefix(info.Path, "/apis/discovery.k8s.io/v1/endpointslices") {
		decoder := getWatchDecoder(resp.Body)
		eventType, obj, err := decoder.Decode()
		if err != nil {
			klog.Errorf("decoder.Decode error: %v,info.Path: %v,info.Verb: %v", err, info.Path, info.Verb)
			return err
		}

		ep := &discoveryv1.EndpointSlice{}
		err = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.(*unstructured.Unstructured).Object, ep)
		if err != nil {
			klog.Errorf("DefaultUnstructuredConverter.FromUnstructured error: %v,info.Path: %v,info.Verb: %v", err, info.Path, info.Verb)
			return err
		}
		if ep.ObjectMeta.Name == "kubernetes" && ep.ObjectMeta.Namespace == "default" {
			p.modifyKubernetesV1EndpointSlice(ep)
		}

		event := &WatchEvent{
			Type:   eventType,
			Object: ep,
		}
		data, err := json.Marshal(event)
		if err != nil {
			klog.Errorf("json.Marshal error: %v,info.Path: %v,info.Verb: %v", err, info.Path, info.Verb)
			return err
		}
		resp.Body = ioutil.NopCloser(bytes.NewBuffer(data))
	} else if strings.HasPrefix(info.Path, "/apis/discovery.k8s.io/v1beta1/endpointslices") {
		decoder := getWatchDecoder(resp.Body)
		eventType, obj, err := decoder.Decode()
		if err != nil {
			klog.Errorf("decoder.Decode error: %v,info.Path: %v,info.Verb: %v", err, info.Path, info.Verb)
			return err
		}

		ep := &discoveryv1beta1.EndpointSlice{}
		err = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.(*unstructured.Unstructured).Object, ep)
		if err != nil {
			klog.Errorf("DefaultUnstructuredConverter.FromUnstructured error: %v,info.Path: %v,info.Verb: %v", err, info.Path, info.Verb)
			return err
		}
		if ep.ObjectMeta.Name == "kubernetes" && ep.ObjectMeta.Namespace == "default" {
			p.modifyKubernetesV1Beta1EndpointSlice(ep)
		}

		event := &WatchEvent{
			Type:   eventType,
			Object: ep,
		}
		data, err := json.Marshal(event)
		if err != nil {
			klog.Errorf("json.Marshal error: %v,info.Path: %v,info.Verb: %v", err, info.Path, info.Verb)
			return err
		}
		resp.Body = ioutil.NopCloser(bytes.NewBuffer(data))
	} else if strings.HasPrefix(info.Path, "/api/v1/services") && p.disableLoadBalancerIngress {
		decoder := getWatchDecoder(resp.Body)
		eventType, obj, err := decoder.Decode()
		if err != nil {
			klog.Errorf("decoder.Decode error: %v,info.Path: %v,info.Verb: %v", err, info.Path, info.Verb)
			return err
		}

		svc := &v1.Service{}
		err = runtime.DefaultUnstructuredConverter.FromUnstructured(obj.(*unstructured.Unstructured).Object, svc)
		if err != nil {
			klog.Errorf("DefaultUnstructuredConverter.FromUnstructured error: %v,info.Path: %v,info.Verb: %v", err, info.Path, info.Verb)
			return err
		}
		if len(svc.Status.LoadBalancer.Ingress) > 0 {
			svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{}
		}

		event := &WatchEvent{
			Type:   eventType,
			Object: svc,
		}
		data, err := json.Marshal(event)
		if err != nil {
			klog.Errorf("json.Marshal error: %v,info.Path: %v,info.Verb: %v", err, info.Path, info.Verb)
			return err
		}
		resp.Body = ioutil.NopCloser(bytes.NewBuffer(data))
	}

	return nil
}

func (p *EdgeReverseProxy) interceptListResponse(info *apirequest.RequestInfo, resp *http.Response) error {
	if info.Verb != constant.VerbList {
		return nil
	}

	// 仅处理下面case，其他场景不处理
	if !strings.HasPrefix(info.Path, "/apis/discovery.k8s.io/v1/endpointslices") &&
		!strings.HasPrefix(info.Path, "/apis/discovery.k8s.io/v1beta1/endpointslices") &&
		!(strings.HasPrefix(info.Path, "/api/v1/services") && p.disableLoadBalancerIngress) {
		return nil
	}

	// 当前只支持gzip压缩和非压缩场景，其他场景仅做日志输出，跳过处理
	if resp.Header.Get("Content-Encoding") != "gzip" && resp.Header.Get("Content-Encoding") != "" {
		klog.Warningf("Content-Encoding %s not support for %v", resp.Header.Get("Content-Encoding"), info.Path)
		return nil
	}

	body, _ := ioutil.ReadAll(resp.Body)
	var data, rspContent []byte
	if resp.Header.Get("Content-Encoding") == "" {
		data = body
	} else {
		gzipReader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return err
		}
		data, err = ioutil.ReadAll(gzipReader)
		if err != nil {
			return err
		}
		gzipReader.Close()
	}

	if strings.HasPrefix(info.Path, "/apis/discovery.k8s.io/v1/endpointslices") {
		objList := &discoveryv1.EndpointSliceList{}
		err := json.Unmarshal(data, objList)
		if err != nil {
			klog.Errorf("json.Unmarshal error: %v,info.Path: %v,info.Verb: %v,body: %v", err, info.Path, info.Verb, string(data))
			return err
		}
		newItems := make([]discoveryv1.EndpointSlice, len(objList.Items))
		for index, ep := range objList.Items {
			if ep.ObjectMeta.Name == "kubernetes" && ep.ObjectMeta.Namespace == "default" {
				p.modifyKubernetesV1EndpointSlice(&ep)
			}
			newItems[index] = ep
		}
		objList.Items = newItems
		rspContent, _ = json.Marshal(objList)
	} else if strings.HasPrefix(info.Path, "/apis/discovery.k8s.io/v1beta1/endpointslices") {
		objList := &discoveryv1beta1.EndpointSliceList{}
		err := json.Unmarshal(data, objList)
		if err != nil {
			klog.Errorf("json.Unmarshal error: %v,info.Path: %v,info.Verb: %v,body: %v", err, info.Path, info.Verb, string(data))
			return err
		}
		newItems := make([]discoveryv1beta1.EndpointSlice, len(objList.Items))
		for index, ep := range objList.Items {
			if ep.ObjectMeta.Name == "kubernetes" && ep.ObjectMeta.Namespace == "default" {
				p.modifyKubernetesV1Beta1EndpointSlice(&ep)
			}
			newItems[index] = ep
		}
		objList.Items = newItems
		rspContent, _ = json.Marshal(objList)
	} else if strings.HasPrefix(info.Path, "/api/v1/services") && p.disableLoadBalancerIngress {
		objList := &v1.ServiceList{}
		err := json.Unmarshal(data, objList)
		if err != nil {
			klog.Errorf("json.Unmarshal error: %v,info.Path: %v,info.Verb: %v,body: %v", err, info.Path, info.Verb, string(data))
			return err
		}
		newItems := make([]v1.Service, len(objList.Items))
		for index, svc := range objList.Items {
			if len(svc.Status.LoadBalancer.Ingress) > 0 {
				svc.Status.LoadBalancer.Ingress = []v1.LoadBalancerIngress{}
			}
			newItems[index] = svc
		}
		objList.Items = newItems
		rspContent, _ = json.Marshal(objList)
	}

	var rspData = bytes.NewBuffer(nil)
	if resp.Header.Get("Content-Encoding") == "" {
		rspData = bytes.NewBuffer(rspContent)
	} else {
		gzipWriter := gzip.NewWriter(rspData)
		if _, err := gzipWriter.Write(rspContent); err != nil {
			return err
		}
		gzipWriter.Close()
	}
	resp.Body = ioutil.NopCloser(rspData)
	return nil
}

func (p *EdgeReverseProxy) interceptResponse(info *apirequest.RequestInfo, resp *http.Response) error {
	if info.Verb == constant.VerbWatch {
		if err := p.interceptWatchResponse(info, resp); err != nil {
			return err
		}
	} else if info.Verb == constant.VerbList {
		if err := p.interceptListResponse(info, resp); err != nil {
			return err
		}
	} //TODO:info.Verb ==constant.VerbGet
	//  /apis/discovery.k8s.io/v1/namespaces/default/endpointslices/kubernetes
	//  /apis/discovery.k8s.io/v1beta1/namespaces/default/endpointslices/kubernetes
	//  pattern := "^/api/v1/namespaces/[^/]+/services/[^/]+"

	// and some VerbList
	//  /apis/discovery.k8s.io/v1/namespaces/default/endpointslices
	//  /apis/discovery.k8s.io/v1beta1/namespaces/default/endpointslices
	//  pattern := "^/api/v1/namespaces/[^/]+/services"

	return nil
}

func (p *EdgeReverseProxy) handlerError(rw http.ResponseWriter, req *http.Request, err error) {
	klog.V(2).Infof("Request url=%s, error=%v", req.URL, err)

	if req.Method == http.MethodPost && strings.HasPrefix(req.URL.Path, "/api/v1/namespaces") && strings.Contains(req.URL.Path, "serviceaccounts") {
		dataObj := req.Context().Value("TokenRequestData")
		var gvk schema.GroupVersionKind
		gvk.Group = "authentication.k8s.io"
		gvk.Version = "v1"
		gvk.Kind = "TokenRequest"
		contentType := req.Header.Get("Content-Type")
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			klog.V(4).Infof("Unexpected content type from the server: %q: %v", contentType, err)
			return
		}
		mediaTypes := scheme.Codecs.SupportedMediaTypes()
		info, ok := runtime.SerializerInfoForMediaType(mediaTypes, mediaType)
		if !ok {
			err = fmt.Errorf("failed to get serializer, mediaType = %s", mediaType)
			return
		}
		tokenReq := authenticationv1.TokenRequest{}
		err = runtime.DecodeInto(info.Serializer, dataObj.([]byte), &tokenReq)
		if err != nil {
			klog.Error("Failed to decode TokenRequest, error: %v", err)
			return
		}
		err = getToken(&tokenReq)
		if err != nil {
			klog.Error("Failed to get token, error: %v", err)
			return
		}

		accept := req.Header.Get("Accept")
		acceptInfo, found := parseAccept(accept, scheme.Codecs.SupportedMediaTypes())
		if !found {
			return
		}
		edata, err := runtime.Encode(acceptInfo.Serializer, &tokenReq)
		if err != nil {
			klog.Errorf("Failed to encode TokenRequest, error: %v", err)
			return
		}

		rw.Header().Set("Content-Type", acceptInfo.MediaType)
		rw.WriteHeader(http.StatusOK)
		_, err = rw.Write(edata)
		if err != nil {
			klog.Error("Failed to write Response, error: %v", err)
		}
		return
	}

	// filter error. if true, not read cache and ignore
	if p.ignoreCache(req, err) {
		klog.V(6).Infof("Ignore request %s", req.URL)
		rw.WriteHeader(http.StatusServiceUnavailable)
		_, err := rw.Write([]byte(err.Error()))
		if err != nil {
			klog.Errorf("Write error response err: %v", err)
		}
		return
	}

	klog.V(4).Infof("Request error, need read data from cache")

	// read cache when request error
	data, cacheErr := p.readCache(req)
	if cacheErr != nil {
		klog.Errorf("Read cache error %v, write though error", cacheErr)
		rw.WriteHeader(http.StatusNotFound)
		_, err := rw.Write([]byte(err.Error()))
		if err != nil {
			klog.Errorf("Write read cache error: %v", err)
		}
		return
	}

	CopyHeader(rw.Header(), data.Header)
	rw.WriteHeader(data.StatusCode)
	_, err = rw.Write(data.Body)
	if err != nil {
		klog.Errorf("Write cache response for %s err: %v", req.URL, err)
	}
}

func (p *EdgeReverseProxy) ignoreCache(r *http.Request, err error) bool {
	// ignore those requests that do not need cache
	if !needCache(r) {
		return true
	}

	if (err == context.Canceled) || (err == context.DeadlineExceeded) {
		return false
	}

	netErr, ok := err.(net.Error)
	if !ok {
		klog.V(4).Infof("Request error is not net err: %+v", err)
		return true
	}
	if netErr.Timeout() {
		return false
	}

	opError, ok := netErr.(*net.OpError)
	if !ok {
		klog.V(4).Infof("Request error is not netop err: %+v", err)
		return true
	}

	switch t := opError.Err.(type) {
	case *os.SyscallError:
		if errno, ok := t.Err.(syscall.Errno); ok {
			klog.V(4).Infof("Request errorno is %+v", errno)
			switch errno {
			case syscall.ECONNREFUSED, syscall.ETIMEDOUT, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.ECONNRESET:
				return false
			default:
				return true
			}
		}
	}

	return false
}

func (p *EdgeReverseProxy) readCache(r *http.Request) (*cache.EdgeCache, error) {
	return p.cacheManager.Query(r)
}

func (p *EdgeReverseProxy) writeCache(req *http.Request, header http.Header, statusCode int, body io.ReadCloser) error {
	return p.cacheManager.Cache(req, statusCode, header, body)
}

func needCache(r *http.Request) (needCache bool) {
	info, ok := apirequest.RequestInfoFrom(r.Context())
	if ok {
		klog.V(4).Infof("request resourceInfo=%+v", info)

		// only cache resource request
		if info.IsResourceRequest {
			needCache = true
			if r.Method != http.MethodGet {
				needCache = false
			}

			if info.Subresource == "log" {
				// do not cache logs
				needCache = false
			}
		}
	} else if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/version") {
		// add cache /version request
		return true
	} else {
		klog.Errorf("no RequestInfo found in the context")
	}
	return needCache
}

func getToken(tokenReq *authenticationv1.TokenRequest) error {
	opts := new(jose.SignerOptions)
	tokenSiger, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("superedge.io")}, opts)
	if err != nil {
		return err
	}

	now := time.Now()
	sc := &jwt.Claims{
		Subject:   tokenReq.Spec.BoundObjectRef.Name,
		Audience:  jwt.Audience{"superedge.io"},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(time.Duration(100) * time.Second)),
	}

	token, err := jwt.Signed(tokenSiger).Claims(sc).CompactSerialize()
	if err != nil {
		return err
	}
	tokenReq.Status.Token = token
	tokenReq.Status.ExpirationTimestamp = metav1.Time{Time: now.Add(time.Duration(100) * time.Second)}
	return nil
}

func parseAccept(header string, accepted []runtime.SerializerInfo) (runtime.SerializerInfo, bool) {
	if len(header) == 0 && len(accepted) > 0 {
		return accepted[0], true
	}

	clauses := goautoneg.ParseAccept(header)
	for i := range clauses {
		clause := &clauses[i]
		for i := range accepted {
			accepts := &accepted[i]
			switch {
			case clause.Type == accepts.MediaTypeType && clause.SubType == accepts.MediaTypeSubType,
				clause.Type == accepts.MediaTypeType && clause.SubType == "*",
				clause.Type == "*" && clause.SubType == "*":
				return *accepts, true
			}
		}
	}
	return runtime.SerializerInfo{}, false
}
