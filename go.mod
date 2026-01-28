module github.com/blackwell-systems/gcp-kms-emulator

go 1.24.0

require (
	cloud.google.com/go/kms v1.25.0
	github.com/blackwell-systems/gcp-emulator-auth v0.0.0-20260126234751-6976d522b21f
	google.golang.org/grpc v1.78.0
	google.golang.org/protobuf v1.36.11
)

require (
	cloud.google.com/go/iam v1.5.3 // indirect
	cloud.google.com/go/longrunning v0.8.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto v0.0.0-20260126211449-d11affda4bed // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260120221211-b8f7ae30c516 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120221211-b8f7ae30c516 // indirect
)

replace github.com/blackwell-systems/gcp-emulator-auth => ../gcp-emulator-auth
