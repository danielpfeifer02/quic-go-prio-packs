module github.com/danielpfeifer02/quic-go-prio-packs

go 1.21

require (
	github.com/francoispqt/gojay v1.2.13
	github.com/onsi/ginkgo/v2 v2.9.5
	github.com/onsi/gomega v1.27.6
	github.com/quic-go/qpack v0.4.0
	go.uber.org/mock v0.3.0
	golang.org/x/exp v0.0.0-20221205204356-47842c84f3db
	golang.org/x/net v0.25.0
	golang.org/x/sync v0.9.0
	golang.org/x/sys v0.27.0
)

require golang.org/x/crypto v0.23.0

replace golang.org/x/crypto v0.23.0 => ../crypto

require (
	github.com/go-logr/logr v1.2.4 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/go-cmp v0.6.0 // indirect
	github.com/google/pprof v0.0.0-20210407192527-94a9f03dee38 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/text v0.20.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
