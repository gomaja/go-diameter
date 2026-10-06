package service

import (
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func Errorf(code codes.Code, format string, a ...interface{}) error {
	msg := fmt.Sprintf(format, a...)
	slog.Info("RPC error", "code", code.String(), "error", msg)
	return status.Errorf(code, "%s", msg)
}

func Error(code codes.Code, err error) error {
	slog.Info("RPC error", "code", code.String(), "error", err)
	return status.Error(code, err.Error())
}
