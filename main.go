package main

import (
	"context"
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/smtp"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

type User struct {
	Email    string
	Username string
	Password string
	key      string
}

var mapLock sync.RWMutex
var preUserMap map[string]*User

const (
	SMTP_HOST     = "smtp.163.com"
	SMTP_PORT     = "25"
	SMTP_USERNAME = "example@163.com"
	SMTP_PASSWORD = "" // authentication code
)

const (
	USERNAME = "" // mysql username
	PASSWORD = "" // mysql password
	IP       = "127.0.0.1"
	PORT     = "3306"
	DBNAME   = "" // database name
)

var db *sql.DB

func initDatabase() {
	path := strings.Join([]string{USERNAME, ":", PASSWORD, "@tcp(", IP, ":", PORT, ")/", DBNAME, "?charset=utf8"}, "")
	db, _ = sql.Open("mysql", path)

	db.SetConnMaxLifetime(100)
	db.SetMaxIdleConns(10)

	if err := db.Ping(); err != nil {
		log.Fatal("sql Ping err")
	}

	fmt.Println("sql connected")
}

func selectUserByEmail(email string) *User {
	var user User

	err := db.QueryRow("SELECT * FROM user where email = ?", email).Scan(&user.Email, &user.Username, &user.Password)
	if err != nil {
		fmt.Println("sql QueryRow err", err)
		return nil
	}

	return &user
}

func inserIntoUser(user *User) bool {
	password := md5.Sum([]byte(user.Password))

	query := "INSERT INTO user VALUES (?, ?, ?)"
	_, err := db.ExecContext(context.Background(), query, user.Email, user.Username, hex.EncodeToString(password[0:]))
	if err != nil {
		fmt.Println("sql ExecContext err", err)
		return false
	}

	return true
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method is not supported", http.StatusNotFound)
		return
	}

	query := r.URL.Query()
	email := query.Get("email")
	key := query.Get("key")

	if email == "" || key == "" {
		return
	}

	mapLock.Lock()
	user, ok := preUserMap[email]
	mapLock.Unlock()

	if !ok {
		fmt.Fprintf(w, "Time out")
		return
	}

	if user.key != key {
		fmt.Fprintln(w, "Incorrect URL")
		return
	}

	if inserIntoUser(user) == false {
		fmt.Fprintln(w, "Sign up failed")
		return
	}

	fmt.Fprintf(w, "Sign up succeed")
}

func signinHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm err: %v", err)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method is not supported", http.StatusNotFound)
		return
	}

	user := selectUserByEmail(r.FormValue("email"))
	if user == nil {
		fmt.Fprintln(w, "No user email")
		return
	}

	password := md5.Sum([]byte(r.FormValue("password")))
	if hex.EncodeToString(password[0:]) != user.Password {
		fmt.Fprintln(w, "Incorrect password")
		return
	}

	fmt.Fprintf(w, "email: %s\n", user.Email)
	fmt.Fprintf(w, "username: %s\n", user.Username)
	fmt.Fprintf(w, "password: %s\n", user.Password)
}

func sendEmail(email string) bool {
	rn := rand.Int31n(math.MaxInt32)
	rk := md5.Sum([]byte(string(rn)))

	mapLock.Lock()
	user, _ := preUserMap[email]
	user.key = hex.EncodeToString(rk[0:])
	preUserMap[email] = user
	mapLock.Unlock()

	body := strings.Join([]string{"http://localhost:23333/verify?email=", email, "&key=", user.key}, "")

	auth := smtp.PlainAuth("", SMTP_USERNAME, SMTP_PASSWORD, SMTP_HOST)
	contentType := "Content-Type: text/html; charset=UTF-8\r\n\r\n"
	msg := strings.Join([]string{"To:", email, "\r\nFrom:", SMTP_USERNAME, "\r\nSubject:Verification\r\n", contentType, body}, "")
	addr := strings.Join([]string{SMTP_HOST, ":", SMTP_PORT}, "")

	err := smtp.SendMail(addr, auth, SMTP_USERNAME, []string{email}, []byte(msg))
	if err != nil {
		return false
	}

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		select {
		case <-ticker.C:
			mapLock.Lock()
			delete(preUserMap, email)
			mapLock.Unlock()
		}
	}()

	return true
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fmt.Fprintf(w, "ParseForm err: %v\n", err)
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method is not supported", http.StatusNotFound)
		return
	}

	user := selectUserByEmail(r.FormValue("email"))
	if user != nil {
		fmt.Fprintln(w, "Email already exists")
		return
	}

	user = &User{
		Email:    r.FormValue("email"),
		Username: r.FormValue("username"),
		Password: r.FormValue("password"),
	}

	if _, ok := preUserMap[user.Email]; ok {
		fmt.Fprintln(w, "Email already send")
		return
	}

	mapLock.Lock()
	preUserMap[user.Email] = user
	mapLock.Unlock()

	if sendEmail(user.Email) == false {
		fmt.Fprintln(w, "Send email failed")
		return
	}

	fmt.Fprintln(w, "Send email succeed")
}

func main() {
	initDatabase()
	defer db.Close()

	preUserMap = make(map[string]*User)

	fileServer := http.FileServer(http.Dir("./static"))
	http.Handle("/", fileServer)

	http.HandleFunc("/verify", verifyHandler)
	http.HandleFunc("/signin", signinHandler)
	http.HandleFunc("/signup", signupHandler)

	if err := http.ListenAndServe("localhost:23333", nil); err != nil {
		log.Fatal(err)
	}
}
