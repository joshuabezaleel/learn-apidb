package main

import (
	"github.com/joshuabezaleel/learn-apidb/app"
)

func main() {
	app := app.App{}
	app.Initialize("postgres", "postgres", "job-board-api-test")

	app.Run(":8080")
}
