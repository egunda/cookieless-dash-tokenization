

To deploy
gcloud run deploy dash-tokenizer   --source .   --platform managed   --region us-central1   --allow-unauthenticated   --project=your-project-name   --set-build-env-vars="GOOGLE_RUNTIME=go122"
