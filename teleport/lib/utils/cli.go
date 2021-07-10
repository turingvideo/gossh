/*
Copyright 2016-2021 Gravitational, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/gravitational/trace"
	log "github.com/sirupsen/logrus"
)

// FatalError is for CLI front-ends: it detects gravitational/trace debugging
// information, sends it to the logger, strips it off and prints a clean message to stderr
func FatalError(err error) {
	fmt.Fprintln(os.Stderr, UserMessageFromError(err))
	os.Exit(1)
}

// UserMessageFromError returns user-friendly error message from error.
// The error message will be formatted for output depending on the debug
// flag
func UserMessageFromError(err error) string {
	if err == nil {
		return ""
	}
	if log.GetLevel() == log.DebugLevel {
		return trace.DebugReport(err)
	}
	var buf bytes.Buffer
	fmt.Fprint(&buf, Color(Red, "ERROR: "))
	formatErrorWriter(err, &buf)
	return buf.String()
}

// formatErrorWriter formats the specified error into the provided writer.
// The error message is escaped if necessary
func formatErrorWriter(err error, w io.Writer) {
	if err == nil {
		return
	}
	if certErr := formatCertError(err); certErr != "" {
		fmt.Fprintln(w, certErr)
		return
	}
	// If the error is a trace error, check if it has a user message embedded in
	// it, if it does, print it, otherwise escape and print the original error.
	if traceErr, ok := err.(*trace.TraceErr); ok {
		for _, message := range traceErr.Messages {
			fmt.Fprintln(w, AllowNewlines(message))
		}
		fmt.Fprintln(w, AllowNewlines(trace.Unwrap(traceErr).Error()))
		return
	}
	strErr := err.Error()
	// Error can be of type trace.proxyError where error message didn't get captured.
	if strErr == "" {
		fmt.Fprintln(w, "please check Teleport's log for more details")
	} else {
		fmt.Fprintln(w, AllowNewlines(err.Error()))
	}
}

func formatCertError(err error) string {
	switch innerError := trace.Unwrap(err).(type) {
	case x509.HostnameError:
		return fmt.Sprintf("Cannot establish https connection to %s:\n%s\n%s\n",
			innerError.Host,
			innerError.Error(),
			"try a different hostname for --proxy or specify --insecure flag if you know what you're doing.")
	case x509.UnknownAuthorityError:
		return `WARNING:
  The proxy you are connecting to has presented a certificate signed by a
  unknown authority. This is most likely due to either being presented
  with a self-signed certificate or the certificate was truly signed by an
  authority not known to the client.
  If you know the certificate is self-signed and would like to ignore this
  error use the --insecure flag.
  If you have your own certificate authority that you would like to use to
  validate the certificate chain presented by the proxy, set the
  SSL_CERT_FILE and SSL_CERT_DIR environment variables respectively and try
  again.
  If you think something malicious may be occurring, contact your Teleport
  system administrator to resolve this issue.
`
	case x509.CertificateInvalidError:
		return fmt.Sprintf(`WARNING:
  The certificate presented by the proxy is invalid: %v.
  Contact your Teleport system administrator to resolve this issue.`, innerError)
	default:
		return ""
	}
}

const (
	// Red is an escape code for red terminal color
	Red = 31
	// Yellow is an escape code for yellow terminal color
	Yellow = 33
	// Blue is an escape code for blue terminal color
	Blue = 36
	// Gray is an escape code for gray terminal color
	Gray = 37
)

// Color formats the string in a terminal escape color
func Color(color int, v interface{}) string {
	return fmt.Sprintf("\x1b[%dm%v\x1b[0m", color, v)
}

// EscapeControl escapes all ANSI escape sequences from string and returns a
// string that is safe to print on the CLI. This is to ensure that malicious
// servers can not hide output. For more details, see:
//   * https://sintonen.fi/advisories/scp-client-multiple-vulnerabilities.txt
func EscapeControl(s string) string {
	if needsQuoting(s) {
		return fmt.Sprintf("%q", s)
	}
	return s
}

// AllowNewlines escapes all ANSI escape sequences except newlines from string and returns a
// string that is safe to print on the CLI. This is to ensure that malicious
// servers can not hide output. For more details, see:
//   * https://sintonen.fi/advisories/scp-client-multiple-vulnerabilities.txt
func AllowNewlines(s string) string {
	if !strings.Contains(s, "\n") {
		return EscapeControl(s)
	}
	parts := strings.Split(s, "\n")
	for i, part := range parts {
		parts[i] = EscapeControl(part)
	}
	return strings.Join(parts, "\n")
}

// needsQuoting returns true if any non-printable characters are found.
func needsQuoting(text string) bool {
	for _, r := range text {
		if !strconv.IsPrint(r) {
			return true
		}
	}
	return false
}
