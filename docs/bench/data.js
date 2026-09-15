window.BENCHMARK_DATA = {
  "lastUpdate": 1789455803182,
  "repoUrl": "https://github.com/moov-io/cryptfs",
  "entries": {
    "moov-io/cryptfs": [
      {
        "commit": {
          "author": {
            "name": "Adam Shannon",
            "username": "adamdecaf",
            "email": "adamkshannon@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "27642bdb39b06365280860296a821828adf85b81",
          "message": "Run Go benchmarks in this repository. (#118)\n\nStore results in docs/bench and label them with the cryptfs commit that\nran, not a hash from moov-io/benchmarks.",
          "timestamp": "2026-09-14T15:13:53Z",
          "url": "https://github.com/moov-io/cryptfs/commit/27642bdb39b06365280860296a821828adf85b81"
        },
        "date": 1789399485397,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 55802,
            "unit": "ns/op\t    4001 B/op\t      25 allocs/op",
            "extra": "21618 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 55802,
            "unit": "ns/op",
            "extra": "21618 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4001,
            "unit": "B/op",
            "extra": "21618 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "21618 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 50802,
            "unit": "ns/op\t   39201 B/op\t      16 allocs/op",
            "extra": "23619 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 50802,
            "unit": "ns/op",
            "extra": "23619 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39201,
            "unit": "B/op",
            "extra": "23619 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "23619 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 19527,
            "unit": "ns/op\t   53694 B/op\t      16 allocs/op",
            "extra": "63594 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 19527,
            "unit": "ns/op",
            "extra": "63594 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53694,
            "unit": "B/op",
            "extra": "63594 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "63594 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 27935,
            "unit": "ns/op\t   41190 B/op\t      16 allocs/op",
            "extra": "40366 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 27935,
            "unit": "ns/op",
            "extra": "40366 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 41190,
            "unit": "B/op",
            "extra": "40366 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "40366 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 27053,
            "unit": "ns/op\t   42307 B/op\t      16 allocs/op",
            "extra": "43956 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 27053,
            "unit": "ns/op",
            "extra": "43956 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42307,
            "unit": "B/op",
            "extra": "43956 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43956 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 26881,
            "unit": "ns/op\t   42396 B/op\t      16 allocs/op",
            "extra": "44448 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 26881,
            "unit": "ns/op",
            "extra": "44448 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42396,
            "unit": "B/op",
            "extra": "44448 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "44448 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 26975,
            "unit": "ns/op\t   41389 B/op\t      16 allocs/op",
            "extra": "44202 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 26975,
            "unit": "ns/op",
            "extra": "44202 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41389,
            "unit": "B/op",
            "extra": "44202 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "44202 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 27044,
            "unit": "ns/op\t   42001 B/op\t      16 allocs/op",
            "extra": "43365 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 27044,
            "unit": "ns/op",
            "extra": "43365 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42001,
            "unit": "B/op",
            "extra": "43365 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43365 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 51859,
            "unit": "ns/op\t   40614 B/op\t      16 allocs/op",
            "extra": "23071 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 51859,
            "unit": "ns/op",
            "extra": "23071 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 40614,
            "unit": "B/op",
            "extra": "23071 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "23071 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 71563,
            "unit": "ns/op\t   39644 B/op\t      16 allocs/op",
            "extra": "16851 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 71563,
            "unit": "ns/op",
            "extra": "16851 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 39644,
            "unit": "B/op",
            "extra": "16851 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16851 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 72328,
            "unit": "ns/op\t   39107 B/op\t      16 allocs/op",
            "extra": "16489 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 72328,
            "unit": "ns/op",
            "extra": "16489 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 39107,
            "unit": "B/op",
            "extra": "16489 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16489 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 100662,
            "unit": "ns/op\t   38270 B/op\t      16 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 100662,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 38270,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Adam Shannon",
            "username": "adamdecaf",
            "email": "adamkshannon@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "27642bdb39b06365280860296a821828adf85b81",
          "message": "Run Go benchmarks in this repository. (#118)\n\nStore results in docs/bench and label them with the cryptfs commit that\nran, not a hash from moov-io/benchmarks.",
          "timestamp": "2026-09-14T15:13:53Z",
          "url": "https://github.com/moov-io/cryptfs/commit/27642bdb39b06365280860296a821828adf85b81"
        },
        "date": 1789400822528,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 62139,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "18937 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 62139,
            "unit": "ns/op",
            "extra": "18937 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "18937 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "18937 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 64805,
            "unit": "ns/op\t   39216 B/op\t      16 allocs/op",
            "extra": "18453 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 64805,
            "unit": "ns/op",
            "extra": "18453 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39216,
            "unit": "B/op",
            "extra": "18453 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "18453 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 21881,
            "unit": "ns/op\t   53758 B/op\t      16 allocs/op",
            "extra": "48446 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 21881,
            "unit": "ns/op",
            "extra": "48446 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53758,
            "unit": "B/op",
            "extra": "48446 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "48446 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 28508,
            "unit": "ns/op\t   41034 B/op\t      16 allocs/op",
            "extra": "41467 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 28508,
            "unit": "ns/op",
            "extra": "41467 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 41034,
            "unit": "B/op",
            "extra": "41467 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41467 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 27461,
            "unit": "ns/op\t   42122 B/op\t      16 allocs/op",
            "extra": "42960 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 27461,
            "unit": "ns/op",
            "extra": "42960 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42122,
            "unit": "B/op",
            "extra": "42960 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42960 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 28248,
            "unit": "ns/op\t   42261 B/op\t      16 allocs/op",
            "extra": "43794 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 28248,
            "unit": "ns/op",
            "extra": "43794 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42261,
            "unit": "B/op",
            "extra": "43794 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43794 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 28436,
            "unit": "ns/op\t   40978 B/op\t      16 allocs/op",
            "extra": "41040 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 28436,
            "unit": "ns/op",
            "extra": "41040 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 40978,
            "unit": "B/op",
            "extra": "41040 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41040 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 28284,
            "unit": "ns/op\t   41664 B/op\t      16 allocs/op",
            "extra": "42206 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 28284,
            "unit": "ns/op",
            "extra": "42206 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 41664,
            "unit": "B/op",
            "extra": "42206 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42206 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 53343,
            "unit": "ns/op\t   39217 B/op\t      16 allocs/op",
            "extra": "22047 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 53343,
            "unit": "ns/op",
            "extra": "22047 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 39217,
            "unit": "B/op",
            "extra": "22047 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22047 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 72229,
            "unit": "ns/op\t   38764 B/op\t      16 allocs/op",
            "extra": "16513 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 72229,
            "unit": "ns/op",
            "extra": "16513 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 38764,
            "unit": "B/op",
            "extra": "16513 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16513 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 72743,
            "unit": "ns/op\t   38728 B/op\t      16 allocs/op",
            "extra": "16903 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 72743,
            "unit": "ns/op",
            "extra": "16903 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38728,
            "unit": "B/op",
            "extra": "16903 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16903 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 104212,
            "unit": "ns/op\t   37617 B/op\t      16 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 104212,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 37617,
            "unit": "B/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "10000 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Adam Shannon",
            "username": "adamdecaf",
            "email": "adamkshannon@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "27642bdb39b06365280860296a821828adf85b81",
          "message": "Run Go benchmarks in this repository. (#118)\n\nStore results in docs/bench and label them with the cryptfs commit that\nran, not a hash from moov-io/benchmarks.",
          "timestamp": "2026-09-14T15:13:53Z",
          "url": "https://github.com/moov-io/cryptfs/commit/27642bdb39b06365280860296a821828adf85b81"
        },
        "date": 1789400963090,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 56231,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "21169 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 56231,
            "unit": "ns/op",
            "extra": "21169 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "21169 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "21169 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 53407,
            "unit": "ns/op\t   39049 B/op\t      16 allocs/op",
            "extra": "21759 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 53407,
            "unit": "ns/op",
            "extra": "21759 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39049,
            "unit": "B/op",
            "extra": "21759 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "21759 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 20570,
            "unit": "ns/op\t   53692 B/op\t      16 allocs/op",
            "extra": "57184 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 20570,
            "unit": "ns/op",
            "extra": "57184 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53692,
            "unit": "B/op",
            "extra": "57184 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "57184 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 28312,
            "unit": "ns/op\t   41106 B/op\t      16 allocs/op",
            "extra": "43438 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 28312,
            "unit": "ns/op",
            "extra": "43438 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 41106,
            "unit": "B/op",
            "extra": "43438 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43438 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 27754,
            "unit": "ns/op\t   42905 B/op\t      16 allocs/op",
            "extra": "43010 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 27754,
            "unit": "ns/op",
            "extra": "43010 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42905,
            "unit": "B/op",
            "extra": "43010 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43010 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 28444,
            "unit": "ns/op\t   42822 B/op\t      16 allocs/op",
            "extra": "42175 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 28444,
            "unit": "ns/op",
            "extra": "42175 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42822,
            "unit": "B/op",
            "extra": "42175 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42175 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 28743,
            "unit": "ns/op\t   41942 B/op\t      16 allocs/op",
            "extra": "41766 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 28743,
            "unit": "ns/op",
            "extra": "41766 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41942,
            "unit": "B/op",
            "extra": "41766 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41766 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 28559,
            "unit": "ns/op\t   42137 B/op\t      16 allocs/op",
            "extra": "41721 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 28559,
            "unit": "ns/op",
            "extra": "41721 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42137,
            "unit": "B/op",
            "extra": "41721 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41721 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 55295,
            "unit": "ns/op\t   39809 B/op\t      16 allocs/op",
            "extra": "22924 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 55295,
            "unit": "ns/op",
            "extra": "22924 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 39809,
            "unit": "B/op",
            "extra": "22924 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22924 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 73029,
            "unit": "ns/op\t   38542 B/op\t      16 allocs/op",
            "extra": "16404 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 73029,
            "unit": "ns/op",
            "extra": "16404 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 38542,
            "unit": "B/op",
            "extra": "16404 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16404 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 72985,
            "unit": "ns/op\t   38317 B/op\t      16 allocs/op",
            "extra": "16382 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 72985,
            "unit": "ns/op",
            "extra": "16382 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38317,
            "unit": "B/op",
            "extra": "16382 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16382 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 97703,
            "unit": "ns/op\t   36030 B/op\t      16 allocs/op",
            "extra": "12434 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 97703,
            "unit": "ns/op",
            "extra": "12434 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 36030,
            "unit": "B/op",
            "extra": "12434 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "12434 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Adam Shannon",
            "username": "adamdecaf",
            "email": "adamkshannon@gmail.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "27642bdb39b06365280860296a821828adf85b81",
          "message": "Run Go benchmarks in this repository. (#118)\n\nStore results in docs/bench and label them with the cryptfs commit that\nran, not a hash from moov-io/benchmarks.",
          "timestamp": "2026-09-14T15:13:53Z",
          "url": "https://github.com/moov-io/cryptfs/commit/27642bdb39b06365280860296a821828adf85b81"
        },
        "date": 1789455802031,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 58685,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "20044 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 58685,
            "unit": "ns/op",
            "extra": "20044 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "20044 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "20044 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 52163,
            "unit": "ns/op\t   39543 B/op\t      16 allocs/op",
            "extra": "23266 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 52163,
            "unit": "ns/op",
            "extra": "23266 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39543,
            "unit": "B/op",
            "extra": "23266 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "23266 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 20115,
            "unit": "ns/op\t   53333 B/op\t      16 allocs/op",
            "extra": "55866 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 20115,
            "unit": "ns/op",
            "extra": "55866 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53333,
            "unit": "B/op",
            "extra": "55866 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "55866 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 28253,
            "unit": "ns/op\t   41156 B/op\t      16 allocs/op",
            "extra": "44246 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 28253,
            "unit": "ns/op",
            "extra": "44246 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 41156,
            "unit": "B/op",
            "extra": "44246 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "44246 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 27718,
            "unit": "ns/op\t   42542 B/op\t      16 allocs/op",
            "extra": "44374 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 27718,
            "unit": "ns/op",
            "extra": "44374 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42542,
            "unit": "B/op",
            "extra": "44374 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "44374 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 28286,
            "unit": "ns/op\t   42273 B/op\t      16 allocs/op",
            "extra": "43012 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 28286,
            "unit": "ns/op",
            "extra": "43012 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42273,
            "unit": "B/op",
            "extra": "43012 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43012 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 28621,
            "unit": "ns/op\t   42034 B/op\t      16 allocs/op",
            "extra": "41983 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 28621,
            "unit": "ns/op",
            "extra": "41983 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 42034,
            "unit": "B/op",
            "extra": "41983 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41983 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 28549,
            "unit": "ns/op\t   41731 B/op\t      16 allocs/op",
            "extra": "42799 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 28549,
            "unit": "ns/op",
            "extra": "42799 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 41731,
            "unit": "B/op",
            "extra": "42799 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42799 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 52843,
            "unit": "ns/op\t   40049 B/op\t      16 allocs/op",
            "extra": "22264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 52843,
            "unit": "ns/op",
            "extra": "22264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 40049,
            "unit": "B/op",
            "extra": "22264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 72044,
            "unit": "ns/op\t   39697 B/op\t      16 allocs/op",
            "extra": "16700 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 72044,
            "unit": "ns/op",
            "extra": "16700 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 39697,
            "unit": "B/op",
            "extra": "16700 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16700 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 72112,
            "unit": "ns/op\t   38924 B/op\t      16 allocs/op",
            "extra": "16558 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 72112,
            "unit": "ns/op",
            "extra": "16558 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38924,
            "unit": "B/op",
            "extra": "16558 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16558 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 98722,
            "unit": "ns/op\t   36766 B/op\t      16 allocs/op",
            "extra": "12072 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 98722,
            "unit": "ns/op",
            "extra": "12072 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 36766,
            "unit": "B/op",
            "extra": "12072 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "12072 times\n4 procs"
          }
        ]
      }
    ]
  }
}