package main

import (
	"crypto/rand"
	"embed"
	"html/template"
	"log"
	"net/http"
	"time"
)

//go:embed templates/*
var templatesFS embed.FS

var (
	tmplIndex  = template.Must(template.ParseFS(templatesFS, "templates/_layout.tmpl", "templates/index.tmpl"))
	tmplLogin  = template.Must(template.ParseFS(templatesFS, "templates/_layout.tmpl", "templates/login.tmpl"))
	tmplSignup = template.Must(template.ParseFS(templatesFS, "templates/_layout.tmpl", "templates/signup.tmpl"))
)

var users Users = NewUsersInmem()

const cookieName = "userid"

func setCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:   cookieName,
		Value:  id,
		MaxAge: int(time.Hour.Seconds()),
	})
}

func deleteCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   cookieName,
		MaxAge: -1,
	})
}

func identify(r *http.Request) *User {
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return nil
	}
	user, exists := users.UserByID(cookie.Value)
	if exists != nil {
		return nil
	}
	return user
}

func index(w http.ResponseWriter, r *http.Request) {
	data := struct {
		User *User
	}{
		User: identify(r),
	}
	tmplIndex.ExecuteTemplate(w, "index.tmpl", data)
}

func login(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Error string
	}
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		user, err := users.UserByName(username)
		if err != nil || user.Password != password {
			w.WriteHeader(http.StatusBadRequest)
			data.Error = "Invalid username or password"
			tmplLogin.ExecuteTemplate(w, "login.tmpl", data)
			return
		}

		setCookie(w, user.ID)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tmplLogin.ExecuteTemplate(w, "login.tmpl", data)
}

func signup(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Error string
	}
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		if _, err := users.UserByName(username); err == nil {
			w.WriteHeader(http.StatusBadRequest)
			data.Error = "Username already taken"
			tmplSignup.ExecuteTemplate(w, "signup.tmpl", data)
			return
		}
		password := r.FormValue("password")
		id := rand.Text()
		users.SetUser(&User{
			ID:       id,
			Name:     username,
			Password: password,
		})

		setCookie(w, id)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	tmplSignup.ExecuteTemplate(w, "signup.tmpl", data)
}

func logout(w http.ResponseWriter, r *http.Request) {
	deleteCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("sawa: ")

	http.HandleFunc("/", index)
	http.HandleFunc("/login", login)
	http.HandleFunc("/signup", signup)
	http.HandleFunc("/logout", logout)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
