package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/buger/jsonparser"

	"github.com/bmizerany/pat"
	_ "github.com/mattn/go-sqlite3"
)

type Plugin struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Plugins []Plugin

type TwoFactorUser struct {
	Name   string `json:"name"`
	Secret string `json:"secret"`
}

var mainDB *sql.DB

var passwordsJSON []byte

func main() {
	db, errOpenDB := sql.Open("sqlite3", "./data.db")
	checkErr(errOpenDB)
	mainDB = db

	passFile, jsonErr := ioutil.ReadFile("./pass.json")
	checkErr(jsonErr)
	passwordsJSON = passFile

	//Try to create tables
	stmt, stmtErr := mainDB.Prepare("CREATE TABLE IF NOT EXISTS plugins (ID INTEGER PRIMARY KEY AUTOINCREMENT, Name text, Version text)")
	checkErr(stmtErr)
	_, sqlerr := stmt.Exec()
	checkErr(sqlerr)

	stmt2, stmt2Err := mainDB.Prepare("CREATE TABLE IF NOT EXISTS twofactor (name text, secret text, unique(name))")
	checkErr(stmt2Err)
	_, sqlerr2 := stmt2.Exec()
	checkErr(sqlerr2)

	r := pat.New()
	r.Get("/api/v2/plugins", http.HandlerFunc(getPlugins))         //get all plugins
	r.Get("/api/v2/plugins/:id", http.HandlerFunc(getPlugin))      //get one plugin
	r.Post("/api/v2/plugins", http.HandlerFunc(addPlugin))         //create a plugin
	r.Patch("/api/v2/plugins/:id", http.HandlerFunc(updatePlugin)) //update a plugin
	r.Del("/api/v2/plugins/:id", http.HandlerFunc(deletePlugin))   //delete a plugin

	r.Post("/api/v2/upload/:id", http.HandlerFunc(uploadPlugin))
	r.Get("/api/v2/download/:id", http.HandlerFunc(downloadPlugin))

	r.Post("/api/v2/2fa", http.HandlerFunc(createTwoFactor)) //get a 2fa QR

	http.Handle("/", r)

	log.Println("-----++++++-----")
	log.Println("SBDevelopment Update Rest API")
	log.Println("Running on port 25565")
	log.Println("-----++++++-----")
	err := http.ListenAndServe(":25565", nil)
	checkErr(err)
}

func createTwoFactor(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling GET request to /api/v2/2fa")

	password := r.FormValue("password")

	dataPassword, _ := jsonparser.GetString(passwordsJSON, "twofactor")

	if password != dataPassword {
		fmt.Fprintf(w, "%s\n", "{\"errors\": \"Invalid password.\"}")
		return
	}

	account := r.FormValue("account")

	secret, qr := generate(account, "SBDUpdates")

	var twoFactorUser TwoFactorUser
	twoFactorUser.Name = account
	twoFactorUser.Secret = secret

	stmt, err := mainDB.Prepare("INSERT OR IGNORE INTO twofactor(name, secret) VALUES (?, ?)")
	checkErr(err)
	_, errExec := stmt.Exec(twoFactorUser.Name, twoFactorUser.Secret)
	checkErr(errExec)

	stmt2, err2 := mainDB.Prepare("UPDATE twofactor SET secret=? WHERE name=?")
	checkErr(err2)
	_, errExec2 := stmt2.Exec(twoFactorUser.Secret, twoFactorUser.Name)
	checkErr(errExec2)

	fmt.Fprintf(w, "%s", string(qr))
}

func getPlugins(w http.ResponseWriter, _ *http.Request) {
	log.Println("Handling GET request to /api/v2/plugins")

	rows, err := mainDB.Query("SELECT * FROM plugins")
	checkErr(err)
	var plugins Plugins
	for rows.Next() {
		var plugin Plugin
		err = rows.Scan(&plugin.ID, &plugin.Name, &plugin.Version)
		checkErr(err)
		plugins = append(plugins, plugin)
	}

	if len(plugins) == 0 { //Geen plugins gevonden
		fmt.Fprintf(w, "%s\n", "{}")
	} else {
		jsonB, errMarshal := json.Marshal(plugins)
		checkErr(errMarshal)

		fmt.Fprintf(w, "%s\n", string(jsonB))
	}
}

func getPlugin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling GET request to /api/v2/plugins/:id")

	id := r.URL.Query().Get(":id")
	stmt, err := mainDB.Prepare("SELECT * FROM plugins WHERE ID = ?")
	checkErr(err)
	rows, errQuery := stmt.Query(id)
	checkErr(errQuery)
	var plugin Plugin
	for rows.Next() {
		err = rows.Scan(&plugin.ID, &plugin.Name, &plugin.Version)
		checkErr(err)
	}

	if plugin.ID == 0 { //Geen geldige plugin
		fmt.Fprintf(w, "%s\n", "{}")
	} else {
		jsonB, errMarshal := json.Marshal(plugin)
		checkErr(errMarshal)
		fmt.Fprintf(w, "%s\n", string(jsonB))
	}
}

func addPlugin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling POST request to /api/v2/plugins/:id")

	username, token := r.FormValue("username"), r.FormValue("token")

	if !checkToken(username, token) {
		fmt.Fprintf(w, "%s\n", "{\"errors\": \"Invalid token.\"}")
		return
	}

	name, version := r.FormValue("name"), r.FormValue("version")
	var plugin Plugin
	plugin.Name = name
	plugin.Version = version
	stmt, err := mainDB.Prepare("INSERT INTO plugins (Name, Version) VALUES (?, ?)")
	checkErr(err)
	result, errExec := stmt.Exec(plugin.Name, plugin.Version)
	checkErr(errExec)
	newID, errLast := result.LastInsertId()
	checkErr(errLast)
	plugin.ID = newID
	jsonB, errMarshal := json.Marshal(plugin)
	checkErr(errMarshal)
	fmt.Fprintf(w, "%s\n", string(jsonB))
}

func updatePlugin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling PATCH request to /api/v2/plugins/:id")

	username, token := r.FormValue("username"), r.FormValue("token")

	if !checkToken(username, token) {
		fmt.Fprintf(w, "%s\n", "{\"errors\": \"Invalid token.\"}")
		return
	}

	name, version := r.FormValue("name"), r.FormValue("version")
	id := r.URL.Query().Get(":id")

	var plugin Plugin
	ID, _ := strconv.ParseInt(id, 10, 0)
	plugin.ID = ID
	plugin.Name = name
	plugin.Version = version

	stmt, err := mainDB.Prepare("UPDATE plugins SET name = ?, version = ? WHERE id = ?")
	checkErr(err)
	result, errExec := stmt.Exec(plugin.Name, plugin.Version, plugin.ID)
	checkErr(errExec)
	rowAffected, errLast := result.RowsAffected()
	checkErr(errLast)
	if rowAffected > 0 {
		jsonB, errMarshal := json.Marshal(plugin)
		checkErr(errMarshal)
		fmt.Fprintf(w, "%s\n", string(jsonB))
	} else {
		fmt.Fprintf(w, "{row_affected=%d}\n", rowAffected)
	}
}

func deletePlugin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling DEL request to /api/v2/plugins/:id")

	id := r.URL.Query().Get(":id")

	stmt, err := mainDB.Prepare("DELETE FROM plugins WHERE id = ?")
	checkErr(err)
	result, errExec := stmt.Exec(id)
	checkErr(errExec)
	rowAffected, errRow := result.RowsAffected()
	checkErr(errRow)
	fmt.Fprintf(w, "{row_affected=%d}\n", rowAffected)
}

func uploadPlugin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling POST request to /api/v2/upload/:id")

	username, token := r.FormValue("username"), r.FormValue("token")

	if !checkToken(username, token) {
		fmt.Fprintf(w, "%s\n", "{\"errors\": \"Invalid token.\"}")
		return
	}

	id := r.URL.Query().Get(":id")

	r.ParseMultipartForm(10 << 20)

	file, handler, err := r.FormFile("file")
	checkErr(err)
	defer file.Close()

	fmt.Printf("Uploaded File: %+v\n", handler.Filename)
	fmt.Printf("File Size: %+v\n", handler.Size)
	fmt.Printf("MIME Header: %+v\n", handler.Header)

	tempFile, err := ioutil.TempFile("uploads", id+".jar")
	checkErr(err)
	defer tempFile.Close()

	fileBytes, err := ioutil.ReadAll(file)
	checkErr(err)
	tempFile.Write(fileBytes)

	fmt.Fprintf(w, "%s\n", "{\"success\": \"Upload is done.\"}")
}

func downloadPlugin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling GET request to /api/v2/download/:id")

	body, err := ioutil.ReadAll(r.Body)
	checkErr(err)
	values, err := url.ParseQuery(string(body))
	checkErr(err)

	license, port := values.Get("license"), values.Get("port")

	id := r.URL.Query().Get(":id")

	if license[0:3] == "TPP" && (id == "7" || id == "4") {

	} else if license[0:2] == "AF" && id == "3" {

	} else if license[0:3] == "TPH" && id == "5" {

	} else {
		fmt.Fprintf(w, "%s\n", "{\"errors\": \"Wrong license for this product.\"}")
		return
	}

	username, _ := jsonparser.GetString(passwordsJSON, "license", "username")
	password, _ := jsonparser.GetString(passwordsJSON, "license", "password")

	client := &http.Client{}
	URL := "https://sbdplugins.nl/wp-json/lmfwc/v2/licenses/" + license
	req, err := http.NewRequest("GET", URL, nil)
	checkErr(err)
	req.SetBasicAuth(username, password)
	resp, err := client.Do(req)
	checkErr(err)
	b, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	checkErr(err)

	fmt.Println(string(b))

	status, _ := jsonparser.GetInt(b, "data", "status")
	timesActivated, _ := jsonparser.GetUnsafeString(b, "data", "timesActivated")
	expiresAt, _ := jsonparser.GetUnsafeString(b, "data", "expiresAt")
	ipCheck, _ := jsonparser.GetBoolean(b, "data", "ipcheck")
	dataPort, _ := jsonparser.GetUnsafeString(b, "data", "port")

	switch status {
	case 2:
		//Do nothing, it's delivered.
		break
	case 3:
		//Do nothing, it's activated.
		break
	default:
		fmt.Fprintf(w, "%s\n", "{\"errors\": \"Invalid license status.\"}")
		return
	}

	if timesActivated == "" || timesActivated == "0" {
		fmt.Fprintf(w, "%s\n", "{\"errors\": \"License is not activated.\"}")
		return
	}

	if expiresAt == "" {
		fmt.Fprintf(w, "%s\n", "{\"errors\": \"License has no expire date.\"}")
		return
	}

	format := "2006-01-02 15:04:05"

	t, err := time.Parse(format, expiresAt)
	checkErr(err)

	if t.Before(time.Now()) {
		fmt.Fprintf(w, "%s\n", "{\"errors\": \"License has expired.\"}")
		return
	}

	if !ipCheck {
		fmt.Fprintf(w, "%s\n", "{\"errors\": \"License has been used with another IP.\"}")
		return
	}

	if dataPort == "" {
		fmt.Fprintf(w, "%s\n", "{\"errors\": \"License has no port.\"}")
		return
	}

	if !checkPort(port, dataPort) {
		fmt.Fprintf(w, "%s\n", "{\"errors\": \"License has been used with another Port.\"}")
		return
	}

	w.Header().Set("Content-Type", "application/java-archive") //Force JAR extension

	http.ServeFile(w, r, "./uploads/"+id+".jar")
}

/* +++++++++++++++++++++++++++++++++++++++++++++++ */

func checkToken(username string, token string) bool {
	stmt, err := mainDB.Prepare("SELECT secret FROM twofactor WHERE name = ?")
	checkErr(err)

	var secret string
	errExec := stmt.QueryRow(username).Scan(&secret)
	checkErr(errExec)

	return validate(secret, token)
}

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func checkPort(input string, dataValue string) bool {
	//STEP 1: Check wildcard
	if dataValue == "*" {
		return true
	}

	//STEP 2: Check equals
	if input == dataValue {
		return true
	}

	//STEP 3: Check range
	if strings.Contains(dataValue, "-") {
		split := strings.Split(dataValue, "-")

		//STEP 3.1: Check if min or max is wildcard
		if split[0] == "*" && split[1] != "*" {
			return input <= split[1]
		} else if split[1] == "*" && split[0] != "*" {
			return split[0] <= input
		} else {
			return (split[0] <= input) && (input <= split[1])
		}
	}

	//ELSE, Invalid
	return false
}
