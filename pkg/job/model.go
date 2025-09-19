package job

import (
	"github.com/aquasecurity/harbor-scanner-grype/pkg/http/api"
	"github.com/aquasecurity/harbor-scanner-grype/pkg/harbor"
)

type Status int

const (
	Queued Status = iota
	Pending
	Finished
	Failed
)

func (s Status) String() string {
	return statusToString[s]
}

var statusToString = map[Status]string{
	Queued:   "Queued",
	Pending:  "Pending",
	Finished: "Finished",
	Failed:   "Failed",
}

type ScanJobKey struct {
	ID        string
	MIMEType  api.MIMEType
	MediaType api.MediaType
}

func (k ScanJobKey) String() string {
	return k.ID
}

type ScanJob struct {
	Key    ScanJobKey
	Status Status
	Error  string
	Report *harbor.ScanReport
}

type Job struct {
	Key  ScanJobKey
	Args Args
}

type Args struct {
	ScanRequest *harbor.ScanRequest
}

func (j Job) ID() string {
	return j.Key.ID
}
