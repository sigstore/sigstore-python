# get service account
#curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/?recursive=true
# get access token, maybe use default?
GOOGLE_SERVICE_ACCOUNT_NAME
TOKEN=$(curl -s --header "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token?scopes=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fcloud-platform | jq -r ".access_token")
echo $TOKEN
# get oidc token, maybe use default?
curl -v -X POST -H "content-type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"audience": "sigstore", "includeEmail": true}' "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sigstore-python-test@projectsigstore.iam.gserviceaccount.com:generateIdToken"
#curl -v -X POST -H "content-type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"audience": "sigstore", "includeEmail": true}' "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/default:generateIdToken"
#curl -v -X POST -H "content-type: application/json" -H "Authorization: Bearer $TOKEN" -d '{"audience": "sigstore", "includeEmail": true}' "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/testing@di-labs.iam.gserviceaccount.com:generateIdToken"
