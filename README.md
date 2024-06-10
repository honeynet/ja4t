# JA4T Fingerprint Parser

This Go package provides a parser for the JA4T (Joint Application Protocol Handler) fingerprint. The parser can read PCAP files and extract JA4T fingerprints from TCP packets.


## Features

- Reads PCAP files using the pcap library
- Parses TCP packets to extract JA4T fingerprints
- Supports parsing of multiple JA4T fingerprints in a single file

## Usage

To use this package, simply import it into your Go program and call the ParseFile function:

```
package main

import (
	"fmt"
	"ja4t"
)

func main() {
	files, err := ja4t.ParseFile("example.pcap")
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, file := range files {
		fmt.Println(file.String())
	}
}
```

## Note

This package is still under development and may contain bugs or incomplete features. Please report any issues you encounter to the maintainer.


## License

This package is licensed under the MIT License. See the LICENSE file for details.


## Acknowledgments

This package was inspired by the work of the Google Packet Capture library (gopacket).
