test:
	go test ./...

all:
	go build -o gateway

logs:
	gcloud app logs tail

deploy:
	gcloud app deploy --stop-previous-version gateway.yaml
