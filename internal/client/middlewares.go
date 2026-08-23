package client

import (
	"context"

	"connectrpc.com/connect"
	"github.com/mizuchilabs/kata/buildinfo"
)

type uaInterceptor struct {
	ua string
}

func withUA() connect.Interceptor {
	return &uaInterceptor{ua: buildinfo.UserAgent("nokkud")}
}

func (a *uaInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set("User-Agent", a.ua)
		return next(ctx, req)
	}
}

func (a *uaInterceptor) WrapStreamingClient(
	next connect.StreamingClientFunc,
) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		conn.RequestHeader().Set("User-Agent", a.ua)
		return conn
	}
}

func (a *uaInterceptor) WrapStreamingHandler(
	next connect.StreamingHandlerFunc,
) connect.StreamingHandlerFunc {
	return next
}
