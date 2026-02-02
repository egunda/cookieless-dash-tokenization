# Cookieless DASH Tokenization

A high-performance solution for tokenizing DASH (Dynamic Adaptive Streaming over HTTP) manifests to enable secure, cookieless streaming. This tool dynamically rewrites `.mpd` manifests to append security tokens to segment URLs, ensuring content security without relying on browser cookies.

## 🚀 Overview

In modern streaming architectures, relying on cookies for authentication can be problematic for legacy devices, cross-domain scenarios, or strict privacy environments. This repository provides a **Cookieless Tokenization** service that acts as a proxy or pre-processor:

1.  **Ingest**: Takes an original DASH manifest (`.mpd`).
2.  **Tokenize**: Appends time-bound, signature-based tokens to every segment and initialization URL within the manifest.
3.  **Deliver**: Returns a secure, tokenized manifest to the player.

## 📂 Repository Structure

The codebase offers two implementations to cover different use cases:

* **`/go`**: Production-ready implementation written in **Go**. Optimized for high concurrency, low latency, and scale.
* **`/python`**: Reference implementation written in **Python**. Useful for prototyping, logic verification, and low-volume testing.

---

## ⚡ Recommendation: handling Scale

**Use the Go implementation for production workloads.**

While the Python version is excellent for understanding the logic, the Go implementation is engineered to handle high throughput with minimal resource overhead.

| Feature | Go (Recommended) | Python |
| :--- | :--- | :--- |
| **Concurrency** | Goroutines (Lightweight) | Threading/AsyncIO |
| **Performance** | Compiled binary, low latency | Interpreted, higher overhead |
| **Best For** | Production, High Traffic, Edge Compute | Testing, POCs, Scripts |

---

## 🛠️ Go Implementation (Production)

### Prerequisites
* Go 1.18 or higher

### Installation
Navigate to the Go directory and build the binary:

```bash
cd go
go mod tidy
go build -o dash-tokenizer

##To deploy Go codes, use the following cli command
gcloud run deploy dash-tokenizer   --source .   --platform managed   --region us-central1   --allow-unauthenticated   --project=your-project-name   --set-build-env-vars="GOOGLE_RUNTIME=go122"
