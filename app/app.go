package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var secretKey = []byte("secretkey")

type contextKey string

const roleContextKey contextKey = "role"

// App struct description
type App struct {
	Router *mux.Router
	DB     *sql.DB
}

// Claims struct description
type Claims struct {
	jwt.StandardClaims
	Username string `json:"username"`
	Role     string `json:"role"`
}

// Initialize function description
func (app *App) Initialize(user, password, dbname string) {
	connectionString := fmt.Sprintf("user=%s password=%s dbname=%s sslmode=disable", user, password, dbname)

	var err error
	app.DB, err = sql.Open("postgres", connectionString)
	if err != nil {
		log.Fatal(err)
	}

	app.Router = mux.NewRouter()
	app.initializeRoutes()
}

// Run function description
func (app *App) Run(addr string) {
	log.Fatal(http.ListenAndServe(addr, app.Router))
}

func (app *App) initializeRoutes() {
	app.Router.HandleFunc("/register", app.registerUser).Methods("POST")
	app.Router.HandleFunc("/login", app.loginUser).Methods("POST")
	app.Router.HandleFunc("/employer-protected", app.authMiddleware(checkEmployerMiddleware(app.employerProtectedEndpoint))).Methods("GET")
	app.Router.HandleFunc("/applicant-protected", app.authMiddleware(checkApplicantMiddleware(app.applicantProtectedEndpoint))).Methods("GET")

	// Endpoints for Employers
	// app.Router.HandleFunc("/employer/{id:[0-9]+", employerAuthMiddleware(app.updateEmployer)).Methods("PUT")

	// Endpoints for Applicants
}

func (app *App) updateEmployer(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid employer ID")
		return
	}

	var employer Employer
	err = json.NewDecoder(r.Body).Decode(&employer)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()
	employer.ID = id

}

func (app *App) employerProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, http.StatusOK, "You are an employer and you are authorized to access this endpoint")
}

func (app *App) applicantProtectedEndpoint(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, http.StatusOK, "You are an applicant and you are authorized to access this endpoint")
}

func (app *App) registerUser(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	err = user.registerUser(app.DB)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if user.Role == "employer" {
		employer := Employer{UserID: user.ID}
		err = employer.registerEmployer(app.DB)
	} else if user.Role == "applicant" {
		applicant := Applicant{UserID: user.ID}
		err = applicant.registerApplicant(app.DB)
	}

	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondWithJSON(w, http.StatusCreated, user)
}

func (app *App) loginUser(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}
	defer r.Body.Close()

	hashedPassword, err := user.loginUser(app.DB)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if !comparePasswords(hashedPassword, []byte(user.Password)) {
		respondWithError(w, http.StatusUnauthorized, "Password is wrong")
		return
	}

	// Get role of the username logged in
	role, err := user.getRole(app.DB)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, err.Error())
		return
	}

	expirationTime := time.Now().Add(5 * time.Minute).Unix()
	claims := &Claims{
		Username: user.Username,
		Role:     role,
		StandardClaims: jwt.StandardClaims{
			Issuer:    "Job board API",
			ExpiresAt: expirationTime,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		respondWithError(w, http.StatusInternalServerError, "Error issuing token")
		return
	}

	respondWithJSON(w, http.StatusOK, tokenString)
}

func (app *App) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := jwt.MapClaims{}
		authorizationHeader := r.Header.Get("Authorization")
		if authorizationHeader != "" {
			bearerToken := strings.Split(authorizationHeader, " ")
			if len(bearerToken) == 2 {
				token, err := jwt.ParseWithClaims(bearerToken[1], claims, func(token *jwt.Token) (interface{}, error) {
					if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
						return nil, fmt.Errorf("There was an error")
					}
					return secretKey, nil
				})
				if err != nil {
					json.NewEncoder(w).Encode(err)
					return
				}
				if token.Valid {
					username := claims["username"].(string)
					user := User{Username: username}
					role, err := user.getRole(app.DB)
					if err != nil {
						json.NewEncoder(w).Encode(err)
					}
					ctx := context.WithValue(r.Context(), roleContextKey, role)
					next(w, r.WithContext(ctx))
				} else {
					json.NewEncoder(w).Encode("Invalid authorization token")
				}
			}
		} else {
			json.NewEncoder(w).Encode("An authorization header is required")
		}
	})
}

func checkEmployerMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := r.Context().Value(roleContextKey).(string)
		if role != "employer" {
			respondWithError(w, http.StatusUnauthorized, "You are not authorized to access this endpoint")
			return
		} else {
			next(w, r)
		}
	})
}

func checkApplicantMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		role := r.Context().Value(roleContextKey).(string)
		if role != "applicant" {
			respondWithError(w, http.StatusUnauthorized, "You are not authorized to access this endpoint")
			return
		} else {
			next(w, r)
		}
	})
}

func comparePasswords(hashedPwd string, plainPwd []byte) bool {
	byteHash := []byte(hashedPwd)

	err := bcrypt.CompareHashAndPassword(byteHash, plainPwd)
	if err != nil {
		log.Println(err)
		return false
	}

	return true
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"Error": message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	w.Write(response)
}
