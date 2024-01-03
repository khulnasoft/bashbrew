package execpipe_test

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/khulnasoft/bashbrew/pkg/execpipe"
)

func Example() {
	pipe, err := execpipe.RunCommand("go", "version")
	if err != nil {
		panic(err)
	}
	defer pipe.Close()

	var buf bytes.Buffer
	io.Copy(&buf, pipe)

	fmt.Println(strings.SplitN(buf.String(), " version ", 2)[0])

	// Output:
	// go
}
