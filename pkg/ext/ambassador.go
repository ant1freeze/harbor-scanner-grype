package ext

import (
	"os"
	"os/exec"
)

type Ambassador interface {
	LookPath(file string) (string, error)
	RunCmd(cmd *exec.Cmd) ([]byte, error)
	Environ() []string
	TempFile(dir, pattern string) (*os.File, error)
}

type ambassador struct{}

func DefaultAmbassador() Ambassador {
	return &ambassador{}
}

func (a *ambassador) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (a *ambassador) RunCmd(cmd *exec.Cmd) ([]byte, error) {
	output, err := cmd.Output()
	return output, err
}

func (a *ambassador) Environ() []string {
	return os.Environ()
}

func (a *ambassador) TempFile(dir, pattern string) (*os.File, error) {
	return os.CreateTemp(dir, pattern)
}
