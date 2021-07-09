/*
Copyright 2016-2020 Gravitational, Inc.
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

package defaults

import "time"

const (
	// Localhost is the address of localhost. Used for the default binding
	// address for port forwarding.
	Localhost = "127.0.0.1"

	// AnyAddress is used to refer to the non-routable meta-address used to
	// refer to all addresses on the machine.
	AnyAddress = "0.0.0.0"

	// TerminalResizePeriod is how long to wait before updating the size of the
	// terminal window.
	TerminalResizePeriod = 2 * time.Second
)
