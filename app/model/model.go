package model

import (
	"database/sql"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User struct description
type User struct {
	ID         int       `json:"id"`
	Username   string    `json:"username"`
	Email      string    `json:"email"`
	Password   string    `json:"password"`
	Role       string    `json:"role"`
	RegisterAt time.Time `json:"registerAt"`
}

// Employer struct description
type Employer struct {
	ID                 int    `json:"ID"`
	UserID             int    `json:"userID"`
	Name               string `json:"name"`
	JobTitle           string `json:"jobTitle"`
	CompanyName        string `json:"companyName"`
	CompanyDescription string `json:"companyDescription"`
	CompanyLogo        string `json:"companyLogo"`
	Employees          string `json:"employees"`
	Industry           string `json:"industry"`
}

// Applicant struct description
type Applicant struct {
	ID       int      `json:"ID"`
	UserID   int      `json:"userID"`
	Name     string   `json:"name"`
	Photo    string   `json:"photo"`
	Location string   `json:"location"`
	Website  []string `json:"website"`
	Summary  string   `json:"summary"`
	Skills   []string `json:"skills"`
}

func (employer *Employer) updateEmployer(db *sql.DB) error {
	_, err := db.Exec("UPDATE employers SET name=$1, job_title=$2, company_name=$3, company_description=$4, company_logo=$5, employees=$6, industry=$7 WHERE id=$8", employer.Name, employer.JobTitle, employer.CompanyName, employer.CompanyDescription, employer.CompanyLogo, employer.Employees, employer.Industry, employer.ID)

	return err
}

func (applicant *Applicant) updateApplicant(db *sql.DB) error {
	_, err := db.Exec("UPDATE applicants SET name=$1, photo=$2, location=$3, website=$4, summary=$5, skills=$6 WHERE id=$7", applicant.Name, applicant.Photo, applicant.Location, applicant.Website, applicant.Summary, applicant.Skills, applicant.ID)

	return err
}

func (user *User) getRole(db *sql.DB) (string, error) {
	result := db.QueryRow("SELECT role FROM users WHERE username=$1", user.Username)

	var role string
	err := result.Scan(&role)
	if err != nil {
		return "", err
	}
	return role, nil
}

func (employer *Employer) registerEmployer(db *sql.DB) error {
	err := db.QueryRow("INSERT INTO employers (user_id) VALUES ($1) RETURNING id", employer.UserID).Scan(&employer.ID)

	if err != nil {
		return err
	}
	return nil
}

func (applicant *Applicant) registerApplicant(db *sql.DB) error {
	err := db.QueryRow("INSERT INTO applicants (user_id) VALUES ($1) RETURNING id", applicant.UserID).Scan(&applicant.ID)

	if err != nil {
		return err
	}
	return nil
}

func hashAndSalt(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}

	return string(hash)
}

func (user *User) registerUser(db *sql.DB) error {
	err := db.QueryRow("INSERT INTO users (username, email, password, role, registered_at) VALUES ($1, $2, $3, $4, $5) RETURNING id", user.Username, user.Email, hashAndSalt([]byte(user.Password)), user.Role, time.Now()).Scan(&user.ID)

	if err != nil {
		return err
	}

	return nil
}

func (user *User) loginUser(db *sql.DB) (string, error) {
	result := db.QueryRow("SELECT password FROM users WHERE username=$1", user.Username)

	storedUser := &User{}
	err := result.Scan(&storedUser.Password)
	if err != nil {
		return "", err
	}

	return storedUser.Password, nil
}
