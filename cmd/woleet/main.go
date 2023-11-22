package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/Squirrel-Entreprise/woleet"
)

func main() {
	wo := woleet.New(os.Getenv("WOLEET_API_KEY"))

	http.HandleFunc("/woleet-callback", func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Error reading request body", http.StatusInternalServerError)
			return
		}

		var anchor woleet.Anchor
		if err := json.Unmarshal(body, &anchor); err != nil {
			http.Error(w, "Error unmarshalling request body", http.StatusInternalServerError)
			return
		}

		r.Body = io.NopCloser(bytes.NewBuffer(body))

		isValid, err := woleet.VerifySignature(r, os.Getenv("WOLEET_CALLBACK_SECRET"))
		if err != nil {
			http.Error(w, fmt.Sprintf("Error verifying signature: %v", err), http.StatusInternalServerError)
			return
		}

		if !isValid {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}

		if anchor.Status == woleet.CONFIRMED {
			// wip
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Callback received and verified"))
	})

	http.HandleFunc("/create-anchro", func(w http.ResponseWriter, r *http.Request) {
		sha, err := woleet.ComputeSHA256Hash("README.md")
		if err != nil {
			log.Println(err)
		}

		callbackUrl := os.Getenv("BASE_URL") + "/woleet_callback"
		public := false
		anchor, err := wo.CreateAnchor(&woleet.CreateAnchorPayload{
			Name: "README.md",
			Hash: sha,
			Metadata: &woleet.Metadata{
				NewKey: "newValue",
			},
			Tags:        []string{"tag1", "tag2"},
			CallbackURL: &callbackUrl,
			Public:      &public,
		})
		if err != nil {
			log.Println(err)
		}

		fmt.Println(anchor)
	})

	http.HandleFunc("/get-anchor", func(w http.ResponseWriter, r *http.Request) {
		anchoID := r.URL.Query().Get("anchorId")
		ancho, err := wo.GetAnchor(anchoID)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}

		jsonData, err := json.Marshal(ancho)
		if err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jsonData)
	})

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
