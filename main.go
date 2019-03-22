package main

import (
	"net/http"

	"github.com/labstack/echo"
	"github.com/piggyman007/echo-session"
)

func main() {
	const redisMaxConnectionPool = 32
	const redisConnection = "localhost:6379"
	const redisPassword = ""
	const redisSecret = "secret"

	e := echo.New()
	store, _ := session.NewRedisStore(redisMaxConnectionPool, "tcp", redisConnection, redisPassword, []byte(redisSecret)) // set redis store
	opts := session.Options{
		MaxAge:   300,                  // sesstion timeout in seconds
		Secure:   true,                 // secure cookie flag
		HttpOnly: true,                 // httponly flag
		SameSite: http.SameSiteLaxMode, // samesite flag
	}
	store.Options(opts)

	e.Use(session.Sessions("EDSESSION", store)) // EDSESSION is the cookie name

	// e.g., http://localhost:8082/login?username=user2&userId=2
	e.GET("/login", func(c echo.Context) error {
		username := c.QueryParam("username")
		userId := c.QueryParam("userId")

		if username != "" && userId != "" {
			session := session.Default(c)
			session.Set("username", username) // save session data
			session.Set("userId", userId)     // save session data
			session.Save()                    // save session
			sessionId := session.GetID()      // get sessionId, need to call GetID() after session.Save()
			return c.JSON(200, map[string]interface{}{
				"msg":       "Login success",
				"sessionId": sessionId,
			})
		}

		return c.JSON(401, map[string]interface{}{
			"msg": "Unauthorized",
		})
	})

	// e.g., http://localhost:8082/profile
	e.GET("/profile", func(c echo.Context) error {
		session := session.Default(c)
		if session.IsNew() {
			return c.JSON(400, map[string]interface{}{
				"msg": "Bad Request",
			})
		}

		username := session.Get("username") // get session data
		userId := session.Get("userId")     // get session data
		session.Save()                      // reset sesstion TTL

		return c.JSON(200, map[string]interface{}{
			"username": username,
			"userId":   userId,
			"sessinId": session.GetID(),
		})
	})

	e.Logger.Fatal(e.Start(":8082"))
}
