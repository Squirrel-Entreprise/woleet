package woleet

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	apiUrl = "https://api.woleet.io/v1"
)

type Woleet struct {
	authToken string
	url       string
	client    *http.Client
}

func New(authToken string) *Woleet {

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	return &Woleet{
		authToken: authToken,
		url:       apiUrl,
		client:    client,
	}
}

type Status string

const (
	// WAIT: waiting to be processed by the platform
	WAIT Status = "WAIT"
	// NEW: waiting to be sent to the blockchain
	NEW Status = "NEW"
	// SENT: sent to the blockchain
	SENT Status = "SENT"
	// CONFIRMED: confirmed at least 6 times by the blockchain
	CONFIRMED Status = "CONFIRMED"
)

type Anchor struct {
	CallbackURL  string   `json:"callbackURL,omitempty"`
	Created      int64    `json:"created,omitempty"`
	Hash         string   `json:"hash,omitempty"`
	ID           string   `json:"id,omitempty"`
	LastModified int64    `json:"lastModified,omitempty"`
	Metadata     Metadata `json:"metadata,omitempty"`
	Name         string   `json:"name,omitempty"`
	Status       Status   `json:"status,omitempty"`
	Tags         []string `json:"tags,omitempty"`
	Timestamp    int64    `json:"timestamp,omitempty"`
	TxID         string   `json:"txId,omitempty"`
}

type CreateAnchorPayload struct {
	Metadata           *Metadata `json:"metadata,omitempty"`
	CallbackURL        *string   `json:"callbackURL,omitempty"`
	Tags               []string  `json:"tags,omitempty"`
	NotifyByEmail      *bool     `json:"notifyByEmail,omitempty"`
	Public             *bool     `json:"public,omitempty"`
	IdentityURL        *string   `json:"identityURL,omitempty"`
	Name               string    `json:"name,omitempty"`
	Hash               string    `json:"hash,omitempty"`
	SignedHash         *string   `json:"signedHash,omitempty"`
	SignedIdentity     *string   `json:"signedIdentity,omitempty"`
	SignedIssuerDomain *string   `json:"signedIssuerDomain,omitempty"`
	PubKey             *string   `json:"pubKey,omitempty"`
	Signature          *string   `json:"signature,omitempty"`
}

type Metadata struct {
	NewKey string `json:"newKey,omitempty"`
}

// CreateAnchor Create a new anchor.
// Use this operation to create a new anchor of one of these two types:
// a data anchor (to generate a proof of timestamp allowing to prove the existence of a data at some point in time)
// a signature anchor (to generate a proof of seal allowing to prove the existence of the signature of a data at some point in time, the validity of the signature and the identity of the signer)
// The properties id, created, lastModified, status, timestamp and confirmations are read-only and so must not be provided: they are managed by the platform and added to the returned anchor.
// For data anchors, only the properties name and hash are required: the hash property must be the SHA256 hash of the data to anchor, and must be computed caller side. This allows not to leak the original data.
// For signature anchors, only the properties name, signedHash, signature and pubKey are required.
// Be sure to have at least 1 timestamp credit (for a data anchor) or 1 seal credit (for a signature anchor).
func (w *Woleet) CreateAnchor(payload *CreateAnchorPayload) (*Anchor, error) {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", w.url+"/anchor", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+w.authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("Unauthorized. The provided token is invalid" + resp.Status)
	}

	if resp.StatusCode == 400 {
		return nil, fmt.Errorf("Invalid request. More details are returned in the response body as a JSON object" + resp.Status)
	}

	if resp.StatusCode == 402 {
		return nil, fmt.Errorf("Insufficient credits. You can buy more credits on the Woleet platform" + resp.Status)
	}

	var anchor Anchor
	if err := json.NewDecoder(resp.Body).Decode(&anchor); err != nil {
		return nil, err
	}

	return &anchor, nil
}

// GetAnchor Get an anchor by its identifier.
// Use this operation to retrieve an anchor by its identifier.
func (w *Woleet) GetAnchor(anchorID string) (*Anchor, error) {
	// https://api.woleet.io/v1/anchor/{anchorId}
	req, err := http.NewRequest("GET", w.url+"/anchor/"+anchorID, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+w.authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("Anchor not found" + resp.Status)
	}

	var anchor Anchor
	if err := json.NewDecoder(resp.Body).Decode(&anchor); err != nil {
		return nil, err
	}

	return &anchor, nil
}

// ComputeSHA256Hash Compute the SHA256 hash of a file.
func ComputeSHA256Hash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	contents, err := ioutil.ReadAll(file)
	if err != nil {
		return "", err
	}

	hasher := sha256.New()
	hasher.Write(contents)
	hashBytes := hasher.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)

	return hashString, nil
}

// ComputeSHA256HashBytes Compute the SHA256 hash of a byte array.
func ComputeSHA256HashBytes(contents []byte) (string, error) {
	hasher := sha256.New()
	hasher.Write(contents)
	hashBytes := hasher.Sum(nil)
	hashString := hex.EncodeToString(hashBytes)

	return hashString, nil
}

// VerifySignature verifies the signature of a Woleet callback
func VerifySignature(r *http.Request, secret string) (bool, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false, err
	}

	mac := hmac.New(sha1.New, []byte(secret))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)

	receivedSig := r.Header.Get("x-woleet-signature")

	decodedSig, err := base64.StdEncoding.DecodeString(receivedSig)
	if err != nil {
		return false, err
	}

	return hmac.Equal(decodedSig, expectedMAC), nil
}

// Download the Proof Attestation document of an anchor.
func (w *Woleet) DownloadProofAttestation(anchorID string) ([]byte, error) {
	req, err := http.NewRequest("GET", w.url+"/anchor/"+anchorID+"/attestation", nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/pdf")
	req.Header.Set("Authorization", "Bearer "+w.authToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("Anchor not found" + resp.Status)
	}

	return io.ReadAll(resp.Body)
}

type Search struct {
	Content          []string `json:"content,omitempty"`
	Empty            bool     `json:"empty,omitempty"`
	First            bool     `json:"first,omitempty"`
	Last             bool     `json:"last,omitempty"`
	Number           int      `json:"number,omitempty"`
	NumberOfElements int      `json:"numberOfElements,omitempty"`
	Pageable         Pageable `json:"pageable,omitempty"`
	Size             int      `json:"size,omitempty"`
	Sort             Sort     `json:"sort,omitempty"`
	TotalElements    int      `json:"totalElements,omitempty"`
	TotalPages       int      `json:"totalPages,omitempty"`
}

type Sort struct {
	Empty    bool `json:"empty,omitempty"`
	Sorted   bool `json:"sorted,omitempty"`
	Unsorted bool `json:"unsorted,omitempty"`
}

type Pageable struct {
	Offset     int  `json:"offset,omitempty"`
	PageNumber int  `json:"pageNumber,omitempty"`
	PageSize   int  `json:"pageSize,omitempty"`
	Paged      bool `json:"paged,omitempty"`
	Sort       Sort `json:"sort,omitempty"`
	Unpaged    bool `json:"unpaged,omitempty"`
}

// SearchPublicAnchors Search for public anchor identifiers.
func (w *Woleet) SearchPublicAnchors(page, size int, hash, signedHash, userId *string) (*Search, error) {
	query := url.Values{}
	query.Add("page", fmt.Sprintf("%d", page))
	query.Add("size", fmt.Sprintf("%d", size))

	if hash != nil {
		query.Add("hash", *hash)
	}

	if signedHash != nil {
		query.Add("signedHash", *signedHash)
	}

	if userId != nil {
		query.Add("userId", *userId)
	}

	req, err := http.NewRequest("GET", w.url+"/anchorIds?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")

	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var search Search
	if err := json.NewDecoder(resp.Body).Decode(&search); err != nil {
		return nil, err
	}

	return &search, nil
}
