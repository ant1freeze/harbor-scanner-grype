module github.com/aquasecurity/harbor-scanner-grype

go 1.26.0

require (
	github.com/caarlos0/env/v6 v6.10.1
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/gorilla/schema v1.4.1
	github.com/prometheus/client_golang v1.24.1
	github.com/redis/go-redis/v9 v9.22.0
	github.com/samber/lo v1.53.0
	github.com/stretchr/testify v1.12.1
	golang.org/x/xerrors v0.0.0-20240903120638-7835f813f4da
	gopkg.in/yaml.v2 v2.4.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.72.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	go.uber.org/atomic v1.12.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/google/go-containerregistry => github.com/knqyf263/go-containerregistry v0.16.2-0.20231101014841-fd95d0f749dd
