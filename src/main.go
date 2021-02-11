package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
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
	log.Println("Handling GET request from ", ReadUserIP(r), " to /api/v2/2fa")

	// Read data from request
	password := r.FormValue("password") //The 2fa password
	account := r.FormValue("account")   //The account name (that get's created)

	// Validate the input
	errs := url.Values{}

	dataPassword, _ := jsonparser.GetString(passwordsJSON, "twofactor") //This is the password in the pass.json file

	if password == "" {
		errs.Add("password", "The password field is required!")
	}

	if password != "" && password != dataPassword {
		errs.Add("password", "The entered password is incorrect!")
	}

	if account == "" {
		errs.Add("account", "The account field is required!")
	}

	// And check if any errors occurred
	if len(errs) > 0 {
		err := map[string]interface{}{"validationError": errs}
		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(err)
		return
	}

	// Generate 2FA account and save to storage
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

	// Return image
	_, _ = fmt.Fprintf(w, "%s", string(qr))
}

func getPlugins(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling GET request from ", ReadUserIP(r), " to /api/v2/plugins")

	// Read data from database
	rows, err := mainDB.Query("SELECT * FROM plugins")
	checkErr(err)
	var plugins Plugins
	for rows.Next() {
		var plugin Plugin
		err = rows.Scan(&plugin.ID, &plugin.Name, &plugin.Version)
		checkErr(err)
		plugins = append(plugins, plugin)
	}

	// And give info back
	if len(plugins) == 0 { // Nothing found?
		_, _ = fmt.Fprintf(w, "%s\n", "{}")
	} else {
		jsonB, errMarshal := json.Marshal(plugins)
		checkErr(errMarshal)

		_, _ = fmt.Fprintf(w, "%s\n", string(jsonB))
	}
}

func getPlugin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling GET request from ", ReadUserIP(r), " to /api/v2/plugins/:id")

	// Read data from request
	id := r.URL.Query().Get(":id")

	// Read data from database
	stmt, err := mainDB.Prepare("SELECT * FROM plugins WHERE ID = ?")
	checkErr(err)
	rows, errQuery := stmt.Query(id)
	checkErr(errQuery)
	var plugin Plugin
	for rows.Next() {
		err = rows.Scan(&plugin.ID, &plugin.Name, &plugin.Version)
		checkErr(err)
	}

	// And give info back
	if plugin.ID == 0 { // Nothing found?
		_, _ = fmt.Fprintf(w, "%s\n", "{}")
	} else {
		jsonB, errMarshal := json.Marshal(plugin)
		checkErr(errMarshal)
		_, _ = fmt.Fprintf(w, "%s\n", string(jsonB))
	}
}

func addPlugin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling POST request from ", ReadUserIP(r), " to /api/v2/plugins/:id")

	// Read data from request
	username, token := r.FormValue("username"), r.FormValue("token")
	name, version := r.FormValue("name"), r.FormValue("version")

	// Validate the input
	errs := url.Values{}

	if username == "" {
		errs.Add("username", "The username field is required!")
	}

	if token == "" {
		errs.Add("token", "The token field is required!")
	}

	if username != "" && token != "" && !checkToken(username, token) {
		errs.Add("token", "The entered token is invalid!")
	}

	if name == "" {
		errs.Add("name", "The name field is required!")
	}

	var versionRegex = regexp.MustCompile(`^(\d+\.)?(\d+\.)?(\*|\d+)$`)

	if version == "" {
		errs.Add("version", "The version field is required!")
	}

	if version != "" && !versionRegex.MatchString(version) { //Using else if structure to be sure that both are empty
		errs.Add("version", "The version field is incorrect!")
	}

	// And check if any errors occurred
	if len(errs) > 0 {
		err := map[string]interface{}{"validationError": errs}
		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(err)
		return
	}

	// Build the structure
	var plugin Plugin
	plugin.Name = name
	plugin.Version = version

	// And insert into the database
	stmt, err := mainDB.Prepare("INSERT INTO plugins (Name, Version) VALUES (?, ?)")
	checkErr(err)
	result, errExec := stmt.Exec(plugin.Name, plugin.Version)
	checkErr(errExec)
	newID, errLast := result.LastInsertId()
	checkErr(errLast)
	plugin.ID = newID
	jsonB, errMarshal := json.Marshal(plugin)
	checkErr(errMarshal)

	// And reply with the JSON of the structure
	_, _ = fmt.Fprintf(w, "%s\n", string(jsonB))
}

func updatePlugin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling PATCH request from ", ReadUserIP(r), " to /api/v2/plugins/:id")

	// Read data from request
	username, token := r.FormValue("username"), r.FormValue("token")
	name, version := r.FormValue("name"), r.FormValue("version")
	id := r.URL.Query().Get(":id")

	// Validate the input
	errs := url.Values{}

	if username == "" {
		errs.Add("username", "The username field is required!")
	}

	if token == "" {
		errs.Add("token", "The token field is required!")
	}

	if username != "" && token != "" && !checkToken(username, token) {
		errs.Add("token", "The entered token is invalid!")
	}

	if name == "" {
		errs.Add("name", "The name field is required!")
	}

	var versionRegex = regexp.MustCompile(`^(\d+\.)?(\d+\.)?(\*|\d+)$`)

	if version == "" {
		errs.Add("version", "The version field is required!")
	}

	if version != "" && !versionRegex.MatchString(version) {
		errs.Add("version", "The version field is incorrect!")
	}

	// And check if any errors occurred
	if len(errs) > 0 {
		err := map[string]interface{}{"validationError": errs}
		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(err)
		return
	}

	// Build the structure
	var plugin Plugin
	ID, _ := strconv.ParseInt(id, 10, 0)
	plugin.ID = ID
	plugin.Name = name
	plugin.Version = version

	// And update in the database
	stmt, err := mainDB.Prepare("UPDATE plugins SET name = ?, version = ? WHERE id = ?")
	checkErr(err)
	result, errExec := stmt.Exec(plugin.Name, plugin.Version, plugin.ID)
	checkErr(errExec)
	rowAffected, errLast := result.RowsAffected()
	checkErr(errLast)

	// And return updated JSON structure if found
	if rowAffected > 0 {
		jsonB, errMarshal := json.Marshal(plugin)
		checkErr(errMarshal)
		_, _ = fmt.Fprintf(w, "%s\n", string(jsonB))
	} else { // Or else return empty JSON
		_, _ = fmt.Fprintf(w, "%s\n", "{}")
	}
}

func deletePlugin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling DEL request from ", ReadUserIP(r), " to /api/v2/plugins/:id")

	// Read data from request
	id := r.URL.Query().Get(":id")

	// Remove from database
	stmt, err := mainDB.Prepare("DELETE FROM plugins WHERE id = ?")
	checkErr(err)
	result, errExec := stmt.Exec(id)
	checkErr(errExec)
	rowAffected, errRow := result.RowsAffected()
	checkErr(errRow)

	// And return success
	_, _ = fmt.Fprintf(w, "{\"success\":%t}\n", rowAffected > 0)
}

func uploadPlugin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling POST request from ", ReadUserIP(r), " to /api/v2/upload/:id")

	// Read data from request
	username, token := r.FormValue("username"), r.FormValue("token")
	id := r.URL.Query().Get(":id")

	_ = r.ParseMultipartForm(10 << 20)
	file, _, err := r.FormFile("file")

	// Validate the input
	errs := url.Values{}

	if file == nil {
		errs.Add("file", "No file was provided.")
	} else {
		checkErr(err)
		defer file.Close()
	}

	if username == "" {
		errs.Add("username", "The username field is required!")
	}

	if token == "" {
		errs.Add("token", "The token field is required!")
	}

	if username != "" && token != "" && !checkToken(username, token) {
		errs.Add("token", "The entered token is invalid!")
	}

	// And check if any errors occurred
	if len(errs) > 0 {
		err := map[string]interface{}{"validationError": errs}
		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(err)
		return
	}

	// Upload the file
	f, err := os.OpenFile("./uploads"+id+".jar", os.O_WRONLY|os.O_CREATE, 0666)
	checkErr(err)
	defer f.Close()

	_, err = io.Copy(f, file)
	checkErr(err)

	// And return success
	_, _ = fmt.Fprintf(w, "{\"success\":%t}\n", true)
}

func downloadPlugin(w http.ResponseWriter, r *http.Request) {
	log.Println("Handling GET request from ", ReadUserIP(r), " to /api/v2/download/:id")

	// Read data from request
	body, err := ioutil.ReadAll(r.Body)
	checkErr(err)
	values, err := url.ParseQuery(string(body))
	checkErr(err)

	license, port := values.Get("license"), values.Get("port")

	id := r.URL.Query().Get(":id")

	// Validate the input
	errs := url.Values{}

	if license == "" {
		errs.Add("license", "The license field is required!")
	}

	if port == "" {
		errs.Add("port", "The port field is required!")
	}

	if license != "" && license[0:3] != "TPP" && license[0:2] != "AF" && license[0:3] != "TPH" {
		errs.Add("license", "The provided license is not for a supported product!")
	}

	if license != "" && (license[0:3] == "TPP" && (id != "7" && id != "4")) || (license[0:2] == "AF" && id != "3") || (license[0:3] == "TPH" && id != "5") {
		errs.Add("license", "The provided ID is for another product than the provided license!")
	}

	// Read username and password for License Manager API from pass.json
	username, _ := jsonparser.GetString(passwordsJSON, "license", "username")
	password, _ := jsonparser.GetString(passwordsJSON, "license", "password")

	// Send request to License Manager API to validate License
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

	// Read the response from the license manager
	status, _ := jsonparser.GetInt(b, "data", "status")
	timesActivated, _ := jsonparser.GetUnsafeString(b, "data", "timesActivated")
	expiresAt, _ := jsonparser.GetUnsafeString(b, "data", "expiresAt")
	ipCheck, _ := jsonparser.GetBoolean(b, "data", "ipcheck")
	dataPort, _ := jsonparser.GetUnsafeString(b, "data", "port")

	// And validate that
	if status != 2 && status != 3 {
		errs.Add("license", "The license is not Delivered or Activated.")
	}

	if timesActivated == "" || timesActivated == "0" {
		errs.Add("license", "The license is not Activated.")
	}

	if expiresAt == "" {
		errs.Add("license", "The license has no expire date.")
	}

	format := "2006-01-02 15:04:05"

	t, err := time.Parse(format, expiresAt)
	checkErr(err)

	if t.Before(time.Now()) {
		errs.Add("license", "The license is expired.")
	}

	if !ipCheck {
		errs.Add("license", "The license has been used with another IP.")
	}

	if dataPort == "" {
		errs.Add("license", "The license has no port.")
	}

	if !checkPort(port, dataPort) {
		errs.Add("license", "The license has been used with another port.")
	}

	// And check if any errors occurred
	if len(errs) > 0 {
		err := map[string]interface{}{"validationError": errs}
		w.Header().Set("Content-type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(err)
		return
	}

	// Serve the file
	w.Header().Set("Content-Type", "application/java-archive") //Force JAR extension
	http.ServeFile(w, r, "./uploads/"+id+".jar")
}

/* +++++++++++++++++++++++++++++++++++++++++++++++ */

func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}

func checkToken(username string, token string) bool {
	username = replaceUsername(username)

	stmt, err := mainDB.Prepare("SELECT secret FROM twofactor WHERE name = ?")
	checkErr(err)

	var secret string
	errExec := stmt.QueryRow(username).Scan(&secret)
	checkErr(errExec)

	return validate(secret, token)
}

func replaceUsername(username string) string {
	regone, err := regexp.Compile("[^0-9a-z-A-Z ]")
	checkErr(err)
	username = regone.ReplaceAllString(username, "")

	regtwo, err := regexp.Compile(" +")
	checkErr(err)
	username = regtwo.ReplaceAllString(username, "_")

	return username
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

// Get the IP of a user, by the request headers.
// This only works if Cloudflare is between it.
// Returns the IP of the user.
func ReadUserIP(r *http.Request) string {
	IPAddress := r.Header.Get("CF-Connecting-IP")
	if IPAddress == "" {
		IPAddress = r.RemoteAddr
	}
	return IPAddress
}
