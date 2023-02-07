package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var db *mongo.Client
var mongoCtx context.Context

//databases
var studentdb *mongo.Collection
var leaverequestdb *mongo.Collection
var leaveresponsedb *mongo.Collection
var Admindb *mongo.Collection

const StudentCollection = "Student"
const LeaverequestCollection = "Leaverequest"
const LeaveresponseCollection = "Leaveresponse"
const leavemanagement = "Leavemanagement"
const Admincollection = "Admin"

func init() {
	mongoCtx = context.Background()
	db, err := mongo.Connect(mongoCtx, options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}
	err = db.Ping(mongoCtx, nil)
	if err != nil {
		log.Fatalf("Could not connect to MongoDB:%v\n", err)
	} else {
		fmt.Println("connected to MongoDB")
	}
	studentdb = db.Database(leavemanagement).Collection(StudentCollection)
	leaverequestdb = db.Database(leavemanagement).Collection(LeaverequestCollection)
	leaveresponsedb = db.Database(leavemanagement).Collection(LeaveresponseCollection)
	Admindb = db.Database(leavemanagement).Collection(Admincollection)
}

type Admin struct {
	Adminname     string `json:"adminname"`
	Adminpassword string `json:"adminpassword"`
}

type login struct {
	Studentname     string `json:"studentname"`
	StudentId       string `json:"studentid"`
	StudentEmail    string `json:"studentemail"`
	Studentpassword string `json:"studentpassword"`
}

type Student struct {
	Studentname     string `json:"studentname"`
	StudentId       string `json:"studentid"`
	StudentEmail    string `json:"studentemail"`
	Studentpassword string `json:studentpassword`
}
type Leaverequest struct {
	Studentname  string `json:"studentname"`
	StudentId    string `json:"studentid"`
	StudentEmail string `json:"studentemail"`
	Reason       string `json:"reason"`
	Duration     string `json:"duration"`
}
type Leaveresponse struct {
	Studentname  string `json:"studentname"`
	StudentId    string `json:"studentid"`
	StudentEmail string `json:"studentemail"`
}
type jsonResponsestudent struct {
	status  int       `json:"type"`
	Data    []Student `json:"data"`
	Message string    `json:"message"`
}
type jsonResponseLeaverequest struct {
	status  int            `json:"type"`
	Data    []Leaverequest `json:"data"`
	Message string         `json:"message"`
}
type jsonResponseLeaveresponse struct {
	status  int             `json:"type"`
	Data    []Leaveresponse `json:"data"`
	Message string          `json:"message"`
}
type jsonResponseLoginresponse struct {
	status int `json:"type"`
	//Data    []Leaveresponse `json:"data"`
	Message string `json:"message"`
	Token   string `json:"token"`
}
type jsonResponseAdmin struct {
	status  int     `json:"type"`
	Data    []Admin `json:"data"`
	Message string  `json:"message"`
	Token   string  `json:"token"`
}

type Claims struct {
	Email string
	jwt.StandardClaims
}

type SuccessResponse struct {
	Status   int
	Message  string
	Response interface{}
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/addstudent", Addstudent).Methods("POST")
	r.HandleFunc("/addleaverequest", Addleaverequest).Methods("POST")
	r.HandleFunc("/getstudents", Getstudents).Methods("GET")
	r.HandleFunc("/addleaveresponse", Addleaversponse).Methods("POST")
	r.HandleFunc("/getleaveresponses", Getleaveresponses).Methods("GET")
	r.HandleFunc("/getleaverequest", Getleaverequests).Methods("GET")
	r.HandleFunc("/loginstudent", loginstudent).Methods("POST")
	r.HandleFunc("/addadmin", Addadmin).Methods("POST")
	r.HandleFunc("/adminlogin", loginAdmin).Methods("POST")
	fmt.Println("attempting to start the server")
	log.Fatal(http.ListenAndServe(":8000", r))
}
func printMessage(message string) {
	fmt.Println("")
	fmt.Println(message)
	fmt.Println("")
}
func checkErr(err error) {
	if err != nil {
		panic(err)
	}
}
func Addstudent(w http.ResponseWriter, r *http.Request) {
	var student Student
	json.NewDecoder(r.Body).Decode(&student)
	fmt.Println("student", student)
	fmt.Println("server started")

	if student.Studentname == "" || student.StudentId == "" || student.StudentEmail == "" {
		json.NewEncoder(w).Encode(jsonResponsestudent{
			status:  400,
			Message: fmt.Sprint("few details are missing in student info"),
		})
	}
	result, err := studentdb.InsertOne(mongoCtx, student)
	if err != nil {
		json.NewEncoder(w).Encode(jsonResponsestudent{
			status:  400,
			Message: fmt.Sprintf("Internal erroe:%v", err),
		})
	}
	w.Header().Set("content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonResponsestudent{
		status:  200,
		Data:    []Student{student},
		Message: fmt.Sprintf("Student created successfully:%s", result.InsertedID),
	})
}
func Addleaversponse(w http.ResponseWriter, r *http.Request) {
	var leaveresponse Leaveresponse
	json.NewDecoder(r.Body).Decode(&leaveresponse)
	fmt.Println("student", leaveresponse)
	fmt.Println("server started")
	result, err := leaveresponsedb.InsertOne(mongoCtx, leaveresponse)
	if err != nil {
		json.NewEncoder(w).Encode(jsonResponseLeaveresponse{
			status:  400,
			Message: fmt.Sprintf("Internal erroe:%v", err),
		})
	}
	w.Header().Set("content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonResponseLeaveresponse{
		status:  200,
		Data:    []Leaveresponse{leaveresponse},
		Message: fmt.Sprintf("Student leave request :%s", result.InsertedID),
	})
}

func Addleaverequest(w http.ResponseWriter, r *http.Request) {
	var leaverequest Leaverequest
	json.NewDecoder(r.Body).Decode(&leaverequest)
	fmt.Println("student", leaverequest)
	fmt.Println("server started")
	result, err := leaverequestdb.InsertOne(mongoCtx, leaverequest)
	if err != nil {
		json.NewEncoder(w).Encode(jsonResponseLeaverequest{
			status:  400,
			Message: fmt.Sprintf("Internal erroe:%v", err),
		})
	}
	w.Header().Set("content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonResponseLeaverequest{
		status:  200,
		Data:    []Leaverequest{leaverequest},
		Message: fmt.Sprintf("Student leave request :%s", result.InsertedID),
	})
}
func Getstudents(w http.ResponseWriter, r *http.Request) {
	var data []Student
	cursor, err := studentdb.Find(context.Background(), bson.M{})
	if err != nil {
		json.NewEncoder(w).Encode(jsonResponsestudent{
			status:  400,
			Message: fmt.Sprintf("unknown internal error:%v", err),
		})
		return
	}
	err = cursor.All(context.Background(), &data)
	if err != nil {
		json.NewEncoder(w).Encode(jsonResponsestudent{
			status:  400,
			Message: fmt.Sprintf("unknown internal error:%v", err),
		})
	}
	res := jsonResponsestudent{
		status:  200,
		Data:    data,
		Message: "Read students successfully",
	}
	defer cursor.Close(context.Background())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&res)
}
func Getleaverequests(w http.ResponseWriter, r *http.Request) {
	var data []Leaverequest
	cursor, err := leaverequestdb.Find(context.Background(), bson.M{})
	if err != nil {
		json.NewEncoder(w).Encode(jsonResponseLeaverequest{
			status:  400,
			Message: fmt.Sprintf("unknown internal error:%v", err),
		})
		return
	}
	err = cursor.All(context.Background(), &data)
	if err != nil {
		json.NewEncoder(w).Encode(jsonResponseLeaverequest{
			status:  400,
			Message: fmt.Sprintf("unknown internal error:%v", err),
		})
	}
	res := jsonResponseLeaverequest{
		status:  200,
		Data:    data,
		Message: "Get students leave request successfully",
	}
	defer cursor.Close(context.Background())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&res)
}
func Getleaveresponses(w http.ResponseWriter, r *http.Request) {
	var data []Leaveresponse
	cursor, err := leaveresponsedb.Find(context.Background(), bson.M{})
	if err != nil {
		json.NewEncoder(w).Encode(jsonResponseLeaveresponse{
			status:  400,
			Message: fmt.Sprintf("unknown internal error:%v", err),
		})
		return
	}
	err = cursor.All(context.Background(), &data)
	if err != nil {
		json.NewEncoder(w).Encode(jsonResponseLeaveresponse{
			status:  400,
			Message: fmt.Sprintf("unknown internal error:%v", err),
		})
	}
	res := jsonResponseLeaveresponse{
		status:  200,
		Data:    data,
		Message: "Read students leave response successfully",
	}
	defer cursor.Close(context.Background())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(&res)
}

//ADDing the admin
func Addadmin(w http.ResponseWriter, r *http.Request) {
	var admin Admin
	json.NewDecoder(r.Body).Decode(&admin)
	fmt.Println("admin", admin)
	fmt.Println("server started")

	if admin.Adminname == "" || admin.Adminpassword == "" {
		json.NewEncoder(w).Encode(jsonResponseAdmin{
			status:  400,
			Message: fmt.Sprint("few details are missing in student info"),
		})
	}
	result, err := Admindb.InsertOne(mongoCtx, admin)
	if err != nil {
		json.NewEncoder(w).Encode(jsonResponseAdmin{
			status:  400,
			Message: fmt.Sprintf("Internal erroe:%v", err),
		})
	}
	w.Header().Set("content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonResponseAdmin{
		status:  200,
		Data:    []Admin{admin},
		Message: fmt.Sprintf("Student created successfully:%s", result.InsertedID),
	})
}
func loginstudent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var loginrequest login
	var result Student
	json.NewDecoder(r.Body).Decode(&loginrequest)
	fmt.Println("login req", len(loginrequest.Studentname))
	if len(loginrequest.Studentname) == 0 {
		// fmt.Println("hello")
		json.NewEncoder(w).Encode(jsonResponseLoginresponse{
			status:  400,
			Message: "Name cannot be empty",
		})
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		query := bson.M{
			"studentname":     loginrequest.Studentname,
			"studentpassword": loginrequest.Studentpassword,
		}
		passwordhashing := loginrequest.Studentpassword
		h := sha256.New()
		h.Write([]byte(passwordhashing))
		loginrequest.Studentpassword = hex.EncodeToString(h.Sum(nil))
		fmt.Println("query is ", query)
		var err = studentdb.FindOne(ctx, query).Decode(&result)

		defer cancel()
		if err != nil {
			json.NewEncoder(w).Encode(jsonResponseLoginresponse{
				status:  400,
				Message: "Name cannot be empty",
			})
		} else {
			tokenstring, _ := CreateJWT(loginrequest.StudentEmail)
			if tokenstring == "" {
				json.NewEncoder(w).Encode(jsonResponseLoginresponse{
					status:  400,
					Message: "It is Null",
				})
			}
			var successResponse = SuccessResponse{
				Status:  http.StatusOK,
				Message: "Login again",
				Response: jsonResponseLoginresponse{
					status:  200,
					Token:   tokenstring,
					Message: fmt.Sprintf("Sucessfully Login %d", &loginrequest.Studentname),
				},
			}

			successjsonResponse, jsonError := json.Marshal(successResponse)
			if jsonError != nil {
				json.NewEncoder(w).Encode(jsonResponseLoginresponse{
					status:  400,
					Message: "cant add the student will null values",
				})
			}

			w.Write(successjsonResponse)
		}
	}
}

var jwtSecretKey = []byte("jwt_secret_key")

func CreateJWT(email string) (response string, err error) {
	expirationTime := time.Now().Add(5 * time.Minute)
	claims := &Claims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecretKey)
	if err == nil {
		return tokenString, nil
	}
	return "", err
}
func VerifyToken(tokenString string) (email string, err error) {
	claims := &Claims{}

	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecretKey, nil
	})

	if token != nil {
		return claims.Email, nil
	}
	return "", err
}
func loginAdmin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var loginrequest Admin
	var result Admin
	json.NewDecoder(r.Body).Decode(&loginrequest)
	fmt.Println("login req", len(loginrequest.Adminname))
	if len(loginrequest.Adminname) == 0 {
		// fmt.Println("hello")
		json.NewEncoder(w).Encode(jsonResponseAdmin{
			status:  400,
			Message: "Name cannot be empty",
		})
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		query := bson.M{
			"adminname":     loginrequest.Adminname,
			"adminpassword": loginrequest.Adminpassword,
		}
		hashpassword := loginrequest.Adminpassword
		h := sha256.New()
		h.Write([]byte(hashpassword))
		loginrequest.Adminpassword = hex.EncodeToString(h.Sum(nil))
		fmt.Println("query is ", query)
		var err = Admindb.FindOne(ctx, query).Decode(&result)

		defer cancel()
		if err != nil {
			json.NewEncoder(w).Encode(jsonResponseAdmin{
				status:  400,
				Message: "Name cannot be empty",
			})
		} else {
			tokenstring, _ := CreateJWT(loginrequest.Adminname)
			if tokenstring == "" {
				json.NewEncoder(w).Encode(jsonResponseAdmin{
					status:  400,
					Message: "It is Null",
				})
			}
			var successResponse = SuccessResponse{
				Status:  http.StatusOK,
				Message: "Login again if you required",
				Response: jsonResponseAdmin{
					status:  200,
					Token:   tokenstring,
					Message: fmt.Sprintf("Sucessfully Login %d", &loginrequest.Adminname),
				},
			}

			successjsonResponse, jsonError := json.Marshal(successResponse)
			if jsonError != nil {
				json.NewEncoder(w).Encode(jsonResponseLoginresponse{
					status:  400,
					Message: "cant add the student will null values",
				})
			}

			w.Write(successjsonResponse)
		}
	}
}
