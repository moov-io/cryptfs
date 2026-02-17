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
	"sync"
)

const (
	minGzipLevel = gzip.NoCompression   // 0
	maxGzipLevel = gzip.BestCompression // 9
)

var (
	gzipWriterPools [maxGzipLevel - minGzipLevel + 1]sync.Pool
	gzipReaderPools [maxGzipLevel - minGzipLevel + 1]sync.Pool
	once            sync.Once
)

func initPools() {
	for i := range gzipWriterPools {
		level := i + minGzipLevel // 0..9
		gzipWriterPools[i] = sync.Pool{
			New: func() any {
				// io.Discard satisfies the non-nil Writer check in NewWriterLevel and does no I/O.
				w, _ := gzip.NewWriterLevel(io.Discard, level)
				return w
			},
		}
		gzipReaderPools[i] = sync.Pool{
			New: func() any {
				// Zero-value *gzip.Reader. Reset() will initialize it on first use.
				// (NewReader() with dummy data fails with ErrHeader, so we can't use it here.)
				return &gzip.Reader{}
			},
		}
	}
}

type gzipCompressor struct {
	strict bool
	level  int
}

// Gzip returns a Compressor using DefaultCompression.
func Gzip() Compressor {
	return &gzipCompressor{level: gzip.DefaultCompression}
}

// GzipLevel returns a Compressor with the specified level.
func GzipLevel(level int) Compressor {
	return &gzipCompressor{level: level}
}

// GzipRequired returns a Compressor that rejects non-gzipped input.
func GzipRequired(level int) Compressor {
	return &gzipCompressor{
		strict: true,
		level:  level,
	}
}

// getPoolIndex normalizes the compression level to a valid pool index (0-9).
// DefaultCompression (-1) maps to 6 (the internal default level in flate).
func (g *gzipCompressor) getPoolIndex() int {
	l := g.level
	if l == gzip.DefaultCompression {
		l = 6
	}
	if l < 0 || l > 9 {
		l = 6 // fallback for invalid levels
	}
	return l
}

func (g *gzipCompressor) compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	once.Do(initPools)

	idx := g.getPoolIndex()
	w, ok := gzipWriterPools[idx].Get().(*gzip.Writer)
	if !ok {
		var err error
		w, err = gzip.NewWriterLevel(io.Discard, idx)
		if err != nil {
			return nil, fmt.Errorf("new gzip writer: %v", err)
		}
	}
	defer gzipWriterPools[idx].Put(w)

	var buf bytes.Buffer
	w.Reset(&buf)

	if _, err := w.Write(data); err != nil {
		// Close is safe to call even on error path
		w.Close()
		return nil, fmt.Errorf("gzip compress write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("gzip compress close: %w", err)
	}

	return buf.Bytes(), nil
}

func (g *gzipCompressor) decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	once.Do(initPools)

	idx := g.getPoolIndex()
	r, ok := gzipReaderPools[idx].Get().(*gzip.Reader)
	if !ok {
		r = &gzip.Reader{} // empty, .Reset() will fix
	}
	defer gzipReaderPools[idx].Put(r)

	// Reset the pooled reader with the input data.
	// For non-gzip input in !strict mode, this returns gzip.ErrHeader.
	if err := r.Reset(bytes.NewReader(data)); err != nil {
		if g.strict {
			return nil, fmt.Errorf("gzip strict reset: %w", err)
		}
		if err == gzip.ErrHeader {
			// Match original behavior: return input data directly (no copy)
			// for non-gzipped content in non-strict mode.
			return data, nil
		}
		return nil, fmt.Errorf("gzip reset: %w", err)
	}

	// Read into a fresh buffer (the real decompression output)
	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		r.Close()
		return nil, fmt.Errorf("gzip decompress copy: %w", err)
	}

	if err := r.Close(); err != nil {
		return nil, fmt.Errorf("gzip decompress close: %w", err)
	}

	return out.Bytes(), nil
}
