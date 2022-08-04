build:
	protoc -I=. --go_out=. *.proto
	go build -o gateway

test:
	go test ./...

all: build test

logs:
	gcloud app logs tail

deploy:
	gcloud app deploy --stop-previous-version gateway.yaml

deploy-protohttp:
	gcloud app deploy --stop-previous-version gateway-protohttp.yaml
