// sawa - Simple Auth Web Application
//
// Example of cookie-based authentication that allows users to sign up, log in,
// and view the current user.
package main

import (
	"crypto/rand"
	"embed"
	"html/template"
	"log"
	"net/http"
	"time"
)

//go:embed templates
var templatesFS embed.FS

var templates = template.Must(template.ParseFS(templatesFS, "templates/*"))

type User struct {
	Name     string
	Password string
}

var users = make(map[string]*User)

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
	user, exists := users[cookie.Value]
	if !exists {
		return nil
	}
	return user
}

func authenticate(username, password string) string {
	for id, user := range users {
		if user.Name == username && user.Password == password {
			return id
		}
	}
	return ""
}

func index(w http.ResponseWriter, r *http.Request) {
	data := struct {
		User *User
	}{
		User: identify(r),
	}
	templates.ExecuteTemplate(w, "index.tmpl", data)
}

func login(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Error string
	}
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		id := authenticate(username, password)
		if id == "" {
			w.WriteHeader(http.StatusBadRequest)
			data.Error = "Invalid username or password"
			templates.ExecuteTemplate(w, "login.tmpl", data)
			return
		}

		setCookie(w, id)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	templates.ExecuteTemplate(w, "login.tmpl", data)
}

func signup(w http.ResponseWriter, r *http.Request) {
	var data struct {
		Error string
	}
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		for _, user := range users {
			if user.Name == username {
				w.WriteHeader(http.StatusBadRequest)
				data.Error = "Username already taken"
				templates.ExecuteTemplate(w, "signup.tmpl", data)
				return
			}
		}
		password := r.FormValue("password")
		id := rand.Text()
		users[id] = &User{
			Name:     username,
			Password: password,
		}

		setCookie(w, id)
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	templates.ExecuteTemplate(w, "signup.tmpl", data)
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
