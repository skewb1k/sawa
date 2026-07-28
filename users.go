package main

import (
	"errors"
)

type Users interface {
	SetUser(user *User) error
	UserByID(id string) (*User, error)
	UserByName(name string) (*User, error)
}

type User struct {
	ID       string
	Name     string
	Password string
}

var (
	ErrUserNotFound = errors.New("user not found")
)

type UsersInmem struct {
	m map[string]*User
}

func NewUsersInmem() *UsersInmem {
	return &UsersInmem{
		m: make(map[string]*User),
	}
}

func (u *UsersInmem) SetUser(user *User) error {
	u.m[user.ID] = user
	return nil
}

func (u *UsersInmem) UserByID(id string) (*User, error) {
	user, exists := u.m[id]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (u *UsersInmem) UserByName(username string) (*User, error) {
	for _, user := range u.m {
		if user.Name == username {
			return user, nil
		}
	}
	return nil, ErrUserNotFound
}
