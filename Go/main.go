// Save this code as main.go
package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// --- Configuration ---

// Global variables to hold configuration from environment variables.
var (
	gcsOriginHost       string
	mediaCDNHost        string
	signingKeyName      string
	tokenLifetimeSeconds int
)

// The ED25519 private key is parsed once at startup and stored here.
var privateKey ed25519.PrivateKey

// The PEM-formatted private key, hardcoded just like in the Python example.
const secretPrivateKeyPEM = `
-----BEGIN PRIVATE KEY-----
MC4C  <your key file here in this line>   S2S+hHuGO5/pkf
-----END PRIVATE KEY-----
`

// --- Regex for Manifest Parsing ---
// We compile these once at startup for efficiency.
// (?i) flag makes the regex case-insensitive.
var (
	urlRegex = regexp.MustCompile(`(?i)(<BaseURL>([^<]+)</BaseURL>)|((?:href|src|media|initialization)\s*=\s*["']([^"']+)["'])`)
	pathToTokenizeRegex = regexp.MustCompile(`(?i)(\.mpd|\.m3u8|\.m4s|\.ts|\.mp4)`)
)


// init() runs before main() and is the ideal place for setup tasks.
func init() {
	// 1. Load configuration from environment variables
	gcsOriginHost = getEnv("GCS_ORIGIN_HOST", "storage.googleapis.com/bucketname")
	mediaCDNHost = getEnv("MEDIA_CDN_HOST", "video.example.com")
	signingKeyName = getEnv("SIGNING_KEY_NAME", "signedkey")
	
	lifetimeStr := getEnv("TOKEN_LIFETIME_SECONDS", "86400")
	lifetime, err := strconv.Atoi(lifetimeStr)
	if err != nil {
		log.Fatalf("FATAL: Invalid TOKEN_LIFETIME_SECONDS value: %v", err)
	}
	tokenLifetimeSeconds = lifetime

	log.Printf("Configuration loaded: MediaCDN Host=[%s], GCS Origin=[%s]", mediaCDNHost, gcsOriginHost)


	// 2. Parse the hardcoded PEM private key
	block, _ := pem.Decode([]byte(secretPrivateKeyPEM))
	if block == nil {
		log.Fatal("FATAL: Failed to decode PEM block from private key")
	}

	genericKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("FATAL: Failed to parse ED25519 private key: %v", err)
	}

	// Type-assert the generic key into the specific ed25519.PrivateKey type
	var ok bool
	privateKey, ok = genericKey.(ed25519.PrivateKey)
	if !ok {
		log.Fatal("FATAL: Key is not a valid ED25519 private key")
	}
}


// getEnv is a helper to read an environment variable or return a default value.
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}


// signURLEd25519 signs a full URL with the expiration time, key name, and signature.
func signURLEd25519(urlToSign string, keyName string) (string, error) {
	expirationTime := time.Now().UTC().Add(time.Duration(tokenLifetimeSeconds) * time.Second)
	expirationTimestamp := expirationTime.Unix()

	// Append Expires and KeyName to create the string that will be signed.
	separator := "?"
	if strings.Contains(urlToSign, "?") {
		separator = "&"
	}
	stringToSign := fmt.Sprintf("%s%sExpires=%d&KeyName=%s", urlToSign, separator, expirationTimestamp, keyName)

	// Sign the string using the pre-parsed private key.
	signatureBytes := ed25519.Sign(privateKey, []byte(stringToSign))

	// URL-safe Base64 encode the signature.
	encodedSignature := base64.URLEncoding.EncodeToString(signatureBytes)

	// Append the signature to the URL.
	signedURL := fmt.Sprintf("%s&Signature=%s", stringToSign, encodedSignature)
	return signedURL, nil
}


// tokenizeManifest scans manifest content, finds media URLs, and replaces them with signed versions.
func tokenizeManifest(manifestContent string, basePath string) (string, error) {
	
	// This function will be called for every URL match found by the regex.
	replacer := func(match string) string {
		// urlRegex has 4 capturing groups.
		// submatches[2] is the URL from a <BaseURL> tag.
		// submatches[4] is the URL from an attribute like href="" or media="".
		submatches := urlRegex.FindStringSubmatch(match)
		
		var originalURL string
		isBaseURLTag := submatches[1] != ""
		if isBaseURLTag {
			originalURL = submatches[2]
		} else {
			originalURL = submatches[4]
		}

		// If the URL doesn't point to a media segment, leave it untouched.
		if !pathToTokenizeRegex.MatchString(originalURL) {
			return match
		}
		
		parsedOriginal, err := url.Parse(originalURL)
		if err != nil {
			log.Printf("Warning: Could not parse URL '%s', skipping. Error: %v", originalURL, err)
			return match // Return original on parse error
		}

		// Determine the full path to sign, handling relative vs. absolute paths.
		var pathForSigning string
		if parsedOriginal.IsAbs() || strings.HasPrefix(parsedOriginal.Path, "/") {
			pathForSigning = parsedOriginal.Path
		} else {
			// This mimics Python's urljoin(base_path + '/', original_url)
			pathForSigning = path.Join(basePath, originalURL)
		}
		
		fullURLToSign := fmt.Sprintf("https://%s%s", mediaCDNHost, pathForSigning)

		// Sign the complete URL.
		signedURLWithParams, err := signURLEd25519(fullURLToSign, signingKeyName)
		if err != nil {
			log.Printf("Warning: Could not sign URL '%s', skipping. Error: %v", fullURLToSign, err)
			return match // Return original on signing error
		}

		// Extract just the query parameters (Expires, KeyName, Signature) from the signed URL.
		parsedSignedURL, _ := url.Parse(signedURLWithParams)
		tokenQuery := parsedSignedURL.RawQuery
		
		// Append the new token parameters to any existing query parameters on the original URL.
		if parsedOriginal.RawQuery != "" {
			parsedOriginal.RawQuery = fmt.Sprintf("%s&%s", parsedOriginal.RawQuery, tokenQuery)
		} else {
			parsedOriginal.RawQuery = tokenQuery
		}

		tokenizedURL := parsedOriginal.String()
		
		// Replace the original URL with the newly tokenized URL inside the original tag/attribute.
		if isBaseURLTag {
			return fmt.Sprintf("<BaseURL>%s</BaseURL>", tokenizedURL)
		} else {
			return strings.Replace(match, originalURL, tokenizedURL, 1)
		}
	}

	// Run the replacer function on the entire manifest content.
	return urlRegex.ReplaceAllStringFunc(manifestContent, replacer), nil
}


// manifestTokenizerHttp is the main HTTP handler for the Cloud Function.
func manifestTokenizerHttp(w http.ResponseWriter, r *http.Request) {
	requestPath := r.URL.Path
	if requestPath == "" || requestPath == "/" {
		http.Error(w, "Please specify a manifest path in the URL.", http.StatusBadRequest)
		return
	}

	// Construct the full URL to download the original manifest from GCS.
	gcsDownloadURL := fmt.Sprintf("https://%s%s", gcsOriginHost, requestPath)
	log.Printf("Fetching manifest from origin: %s", gcsDownloadURL)

	// Fetch the manifest.
	resp, err := http.Get(gcsDownloadURL)
	if err != nil {
		log.Printf("Error fetching manifest from GCS: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Origin returned non-200 status: %d", resp.StatusCode)
		// Pass through the origin's error status code if possible.
		http.Error(w, fmt.Sprintf("Error fetching manifest from origin: Status %d", resp.StatusCode), resp.StatusCode)
		return
	}
	
	manifestContent, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading manifest body: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Tokenize the manifest.
	basePath := path.Dir(requestPath)
	tokenizedManifest, err := tokenizeManifest(string(manifestContent), basePath)
	if err != nil {
		log.Printf("Error tokenizing manifest: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return the tokenized manifest to the client.
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(tokenizedManifest))
}


// main is the entry point of the application.
func main() {
	// Cloud Run sets the PORT environment variable to tell us which port to listen on.
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	// Register our HTTP handler function for all requests.
	http.HandleFunc("/", manifestTokenizerHttp)

	log.Printf("Listening on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}
