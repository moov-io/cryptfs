// Licensed to The Moov Authors under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. The Moov Authors licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package cryptfs

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

type gzipCompressor struct {
	strict bool // prevent non-gzipped content
	level  int
}

func Gzip() Compressor {
	return &gzipCompressor{
		level: gzip.DefaultCompression,
	}
}

// GzipLevel allows callers to specify the compression level.
// Refer to compress/gzip.DefaultCompression and other values for more details.
func GzipLevel(level int) Compressor {
	return &gzipCompressor{
		level: level,
	}
}

// GzipRequired forces the Compressor to only allow gzipped data to be decompressed.
//
// Refer to compress/gzip.DefaultCompression and other values for more details on levels.
func GzipRequired(level int) Compressor {
	return &gzipCompressor{
		strict: true,
		level:  level,
	}
}

func (g *gzipCompressor) compress(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := gzip.NewWriterLevel(&buf, g.level)
	if err != nil {
		return nil, fmt.Errorf("gzip writer (level=%d) create: %w", g.level, err)
	}
	_, err = w.Write(data)
	if err != nil {
		w.Close()
		return nil, fmt.Errorf("gzip compress: %w", err)
	}
	err = w.Close()
	if err != nil {
		return nil, fmt.Errorf("gzip writer close: %w", err)
	}
	return buf.Bytes(), nil
}

func (g *gzipCompressor) decompress(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		if g.strict {
			return nil, fmt.Errorf("gzip strict reader: %w", err)
		}
		if !g.strict && err == gzip.ErrHeader {
			return data, nil
		}
	}
	bs, err := io.ReadAll(r)
	if err != nil {
		r.Close()
		return nil, fmt.Errorf("gzip read: %w", err)
	}
	err = r.Close()
	if err != nil {
		return nil, fmt.Errorf("gzip read close: %w", err)
	}
	return bs, nil
}
