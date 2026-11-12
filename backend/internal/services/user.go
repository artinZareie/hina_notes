package services

import (
	"context"
)

type UserService struct{}

func NewUserService() *UserService { return &UserService{} }

func (s *UserService) SayHello(_ context.Context) (string, error) {
	return "welcome!", nil
}
