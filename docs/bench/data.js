window.BENCHMARK_DATA = {
  "lastUpdate": 1791275141011,
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
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "e07344b6f0287351ecc1b88dd310c0199bce2c65",
          "message": "chore(deps): update benchmark-action/github-action-benchmark action to v1.22.2 (#120)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-15T22:12:42Z",
          "url": "https://github.com/moov-io/cryptfs/commit/e07344b6f0287351ecc1b88dd310c0199bce2c65"
        },
        "date": 1789542257535,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 38160,
            "unit": "ns/op\t    4001 B/op\t      25 allocs/op",
            "extra": "31449 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 38160,
            "unit": "ns/op",
            "extra": "31449 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4001,
            "unit": "B/op",
            "extra": "31449 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "31449 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 28300,
            "unit": "ns/op\t   38674 B/op\t      16 allocs/op",
            "extra": "41403 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 28300,
            "unit": "ns/op",
            "extra": "41403 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 38674,
            "unit": "B/op",
            "extra": "41403 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41403 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 11010,
            "unit": "ns/op\t   52397 B/op\t      16 allocs/op",
            "extra": "107356 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 11010,
            "unit": "ns/op",
            "extra": "107356 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 52397,
            "unit": "B/op",
            "extra": "107356 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "107356 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 15281,
            "unit": "ns/op\t   40198 B/op\t      16 allocs/op",
            "extra": "77026 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 15281,
            "unit": "ns/op",
            "extra": "77026 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 40198,
            "unit": "B/op",
            "extra": "77026 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "77026 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 16119,
            "unit": "ns/op\t   41829 B/op\t      16 allocs/op",
            "extra": "74954 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 16119,
            "unit": "ns/op",
            "extra": "74954 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 41829,
            "unit": "B/op",
            "extra": "74954 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "74954 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 15917,
            "unit": "ns/op\t   41733 B/op\t      16 allocs/op",
            "extra": "71991 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 15917,
            "unit": "ns/op",
            "extra": "71991 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 41733,
            "unit": "B/op",
            "extra": "71991 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "71991 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 16088,
            "unit": "ns/op\t   41325 B/op\t      16 allocs/op",
            "extra": "74766 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 16088,
            "unit": "ns/op",
            "extra": "74766 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41325,
            "unit": "B/op",
            "extra": "74766 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "74766 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 16160,
            "unit": "ns/op\t   41159 B/op\t      16 allocs/op",
            "extra": "75132 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 16160,
            "unit": "ns/op",
            "extra": "75132 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 41159,
            "unit": "B/op",
            "extra": "75132 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "75132 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 28697,
            "unit": "ns/op\t   38922 B/op\t      16 allocs/op",
            "extra": "41862 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 28697,
            "unit": "ns/op",
            "extra": "41862 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 38922,
            "unit": "B/op",
            "extra": "41862 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41862 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 39530,
            "unit": "ns/op\t   38649 B/op\t      16 allocs/op",
            "extra": "30549 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 39530,
            "unit": "ns/op",
            "extra": "30549 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 38649,
            "unit": "B/op",
            "extra": "30549 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "30549 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 39890,
            "unit": "ns/op\t   38691 B/op\t      16 allocs/op",
            "extra": "30172 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 39890,
            "unit": "ns/op",
            "extra": "30172 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38691,
            "unit": "B/op",
            "extra": "30172 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "30172 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 63315,
            "unit": "ns/op\t   38105 B/op\t      16 allocs/op",
            "extra": "18870 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 63315,
            "unit": "ns/op",
            "extra": "18870 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 38105,
            "unit": "B/op",
            "extra": "18870 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "18870 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "e07344b6f0287351ecc1b88dd310c0199bce2c65",
          "message": "chore(deps): update benchmark-action/github-action-benchmark action to v1.22.2 (#120)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-15T22:12:42Z",
          "url": "https://github.com/moov-io/cryptfs/commit/e07344b6f0287351ecc1b88dd310c0199bce2c65"
        },
        "date": 1789628402976,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 23866,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "49695 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 23866,
            "unit": "ns/op",
            "extra": "49695 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "49695 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "49695 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 40369,
            "unit": "ns/op\t   41128 B/op\t      16 allocs/op",
            "extra": "29181 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 40369,
            "unit": "ns/op",
            "extra": "29181 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 41128,
            "unit": "B/op",
            "extra": "29181 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "29181 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 16592,
            "unit": "ns/op\t   54048 B/op\t      16 allocs/op",
            "extra": "69201 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 16592,
            "unit": "ns/op",
            "extra": "69201 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 54048,
            "unit": "B/op",
            "extra": "69201 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "69201 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 21890,
            "unit": "ns/op\t   41249 B/op\t      16 allocs/op",
            "extra": "55440 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 21890,
            "unit": "ns/op",
            "extra": "55440 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 41249,
            "unit": "B/op",
            "extra": "55440 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "55440 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 22095,
            "unit": "ns/op\t   43094 B/op\t      16 allocs/op",
            "extra": "53859 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 22095,
            "unit": "ns/op",
            "extra": "53859 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 43094,
            "unit": "B/op",
            "extra": "53859 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "53859 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 22243,
            "unit": "ns/op\t   42578 B/op\t      16 allocs/op",
            "extra": "53365 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 22243,
            "unit": "ns/op",
            "extra": "53365 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42578,
            "unit": "B/op",
            "extra": "53365 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "53365 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 23482,
            "unit": "ns/op\t   42331 B/op\t      16 allocs/op",
            "extra": "51775 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 23482,
            "unit": "ns/op",
            "extra": "51775 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 42331,
            "unit": "B/op",
            "extra": "51775 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "51775 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 22668,
            "unit": "ns/op\t   42672 B/op\t      16 allocs/op",
            "extra": "52105 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 22668,
            "unit": "ns/op",
            "extra": "52105 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42672,
            "unit": "B/op",
            "extra": "52105 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "52105 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 41019,
            "unit": "ns/op\t   40624 B/op\t      16 allocs/op",
            "extra": "29526 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 41019,
            "unit": "ns/op",
            "extra": "29526 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 40624,
            "unit": "B/op",
            "extra": "29526 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "29526 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 68808,
            "unit": "ns/op\t   36360 B/op\t      16 allocs/op",
            "extra": "17440 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 68808,
            "unit": "ns/op",
            "extra": "17440 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 36360,
            "unit": "B/op",
            "extra": "17440 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "17440 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 69166,
            "unit": "ns/op\t   37152 B/op\t      16 allocs/op",
            "extra": "17289 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 69166,
            "unit": "ns/op",
            "extra": "17289 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 37152,
            "unit": "B/op",
            "extra": "17289 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "17289 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 91245,
            "unit": "ns/op\t   35837 B/op\t      16 allocs/op",
            "extra": "13286 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 91245,
            "unit": "ns/op",
            "extra": "13286 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 35837,
            "unit": "B/op",
            "extra": "13286 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "13286 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "e07344b6f0287351ecc1b88dd310c0199bce2c65",
          "message": "chore(deps): update benchmark-action/github-action-benchmark action to v1.22.2 (#120)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-15T22:12:42Z",
          "url": "https://github.com/moov-io/cryptfs/commit/e07344b6f0287351ecc1b88dd310c0199bce2c65"
        },
        "date": 1789714595848,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 46619,
            "unit": "ns/op\t    4001 B/op\t      25 allocs/op",
            "extra": "27470 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 46619,
            "unit": "ns/op",
            "extra": "27470 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4001,
            "unit": "B/op",
            "extra": "27470 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "27470 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 38926,
            "unit": "ns/op\t   38639 B/op\t      16 allocs/op",
            "extra": "31028 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 38926,
            "unit": "ns/op",
            "extra": "31028 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 38639,
            "unit": "B/op",
            "extra": "31028 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "31028 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 14910,
            "unit": "ns/op\t   52753 B/op\t      16 allocs/op",
            "extra": "82328 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 14910,
            "unit": "ns/op",
            "extra": "82328 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 52753,
            "unit": "B/op",
            "extra": "82328 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "82328 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 20311,
            "unit": "ns/op\t   40931 B/op\t      16 allocs/op",
            "extra": "59115 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 20311,
            "unit": "ns/op",
            "extra": "59115 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 40931,
            "unit": "B/op",
            "extra": "59115 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "59115 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 20268,
            "unit": "ns/op\t   42592 B/op\t      16 allocs/op",
            "extra": "59877 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 20268,
            "unit": "ns/op",
            "extra": "59877 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42592,
            "unit": "B/op",
            "extra": "59877 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "59877 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 20742,
            "unit": "ns/op\t   42433 B/op\t      16 allocs/op",
            "extra": "60266 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 20742,
            "unit": "ns/op",
            "extra": "60266 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42433,
            "unit": "B/op",
            "extra": "60266 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "60266 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 21212,
            "unit": "ns/op\t   41691 B/op\t      16 allocs/op",
            "extra": "56956 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 21212,
            "unit": "ns/op",
            "extra": "56956 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41691,
            "unit": "B/op",
            "extra": "56956 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "56956 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 20554,
            "unit": "ns/op\t   41852 B/op\t      16 allocs/op",
            "extra": "57298 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 20554,
            "unit": "ns/op",
            "extra": "57298 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 41852,
            "unit": "B/op",
            "extra": "57298 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "57298 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 39015,
            "unit": "ns/op\t   38889 B/op\t      16 allocs/op",
            "extra": "30721 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 39015,
            "unit": "ns/op",
            "extra": "30721 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 38889,
            "unit": "B/op",
            "extra": "30721 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "30721 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 56042,
            "unit": "ns/op\t   39426 B/op\t      16 allocs/op",
            "extra": "21537 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 56042,
            "unit": "ns/op",
            "extra": "21537 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 39426,
            "unit": "B/op",
            "extra": "21537 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "21537 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 55421,
            "unit": "ns/op\t   39094 B/op\t      16 allocs/op",
            "extra": "21706 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 55421,
            "unit": "ns/op",
            "extra": "21706 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 39094,
            "unit": "B/op",
            "extra": "21706 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "21706 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 75206,
            "unit": "ns/op\t   37719 B/op\t      16 allocs/op",
            "extra": "15937 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 75206,
            "unit": "ns/op",
            "extra": "15937 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 37719,
            "unit": "B/op",
            "extra": "15937 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15937 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "a7019828f651636b614d0ebec9402ebac2b1562c",
          "message": "chore(deps): update github/codeql-action action to v4.38.1 (#121)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-18T23:28:09Z",
          "url": "https://github.com/moov-io/cryptfs/commit/a7019828f651636b614d0ebec9402ebac2b1562c"
        },
        "date": 1789800911730,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 58601,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "20184 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 58601,
            "unit": "ns/op",
            "extra": "20184 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "20184 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "20184 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 51053,
            "unit": "ns/op\t   40151 B/op\t      16 allocs/op",
            "extra": "23421 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 51053,
            "unit": "ns/op",
            "extra": "23421 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 40151,
            "unit": "B/op",
            "extra": "23421 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "23421 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 22314,
            "unit": "ns/op\t   53635 B/op\t      16 allocs/op",
            "extra": "50030 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 22314,
            "unit": "ns/op",
            "extra": "50030 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53635,
            "unit": "B/op",
            "extra": "50030 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "50030 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 27892,
            "unit": "ns/op\t   40793 B/op\t      16 allocs/op",
            "extra": "43326 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 27892,
            "unit": "ns/op",
            "extra": "43326 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 40793,
            "unit": "B/op",
            "extra": "43326 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43326 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 27470,
            "unit": "ns/op\t   42267 B/op\t      16 allocs/op",
            "extra": "44124 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 27470,
            "unit": "ns/op",
            "extra": "44124 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42267,
            "unit": "B/op",
            "extra": "44124 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "44124 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 27607,
            "unit": "ns/op\t   42176 B/op\t      16 allocs/op",
            "extra": "43027 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 27607,
            "unit": "ns/op",
            "extra": "43027 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42176,
            "unit": "B/op",
            "extra": "43027 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43027 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 27859,
            "unit": "ns/op\t   41627 B/op\t      16 allocs/op",
            "extra": "41887 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 27859,
            "unit": "ns/op",
            "extra": "41887 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41627,
            "unit": "B/op",
            "extra": "41887 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41887 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 27930,
            "unit": "ns/op\t   42161 B/op\t      16 allocs/op",
            "extra": "43549 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 27930,
            "unit": "ns/op",
            "extra": "43549 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42161,
            "unit": "B/op",
            "extra": "43549 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43549 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 52057,
            "unit": "ns/op\t   39096 B/op\t      16 allocs/op",
            "extra": "22958 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 52057,
            "unit": "ns/op",
            "extra": "22958 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 39096,
            "unit": "B/op",
            "extra": "22958 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22958 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 72046,
            "unit": "ns/op\t   38115 B/op\t      16 allocs/op",
            "extra": "16635 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 72046,
            "unit": "ns/op",
            "extra": "16635 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 38115,
            "unit": "B/op",
            "extra": "16635 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16635 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 72525,
            "unit": "ns/op\t   38259 B/op\t      16 allocs/op",
            "extra": "16311 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 72525,
            "unit": "ns/op",
            "extra": "16311 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38259,
            "unit": "B/op",
            "extra": "16311 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16311 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 103408,
            "unit": "ns/op\t   38849 B/op\t      16 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 103408,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 38849,
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
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "a7019828f651636b614d0ebec9402ebac2b1562c",
          "message": "chore(deps): update github/codeql-action action to v4.38.1 (#121)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-18T23:28:09Z",
          "url": "https://github.com/moov-io/cryptfs/commit/a7019828f651636b614d0ebec9402ebac2b1562c"
        },
        "date": 1789888821174,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 56302,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "21004 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 56302,
            "unit": "ns/op",
            "extra": "21004 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "21004 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "21004 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 52507,
            "unit": "ns/op\t   40039 B/op\t      16 allocs/op",
            "extra": "22840 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 52507,
            "unit": "ns/op",
            "extra": "22840 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 40039,
            "unit": "B/op",
            "extra": "22840 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22840 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 20880,
            "unit": "ns/op\t   53118 B/op\t      16 allocs/op",
            "extra": "54466 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 20880,
            "unit": "ns/op",
            "extra": "54466 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53118,
            "unit": "B/op",
            "extra": "54466 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "54466 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 28490,
            "unit": "ns/op\t   40523 B/op\t      16 allocs/op",
            "extra": "42910 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 28490,
            "unit": "ns/op",
            "extra": "42910 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 40523,
            "unit": "B/op",
            "extra": "42910 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42910 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 27204,
            "unit": "ns/op\t   42410 B/op\t      16 allocs/op",
            "extra": "43506 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 27204,
            "unit": "ns/op",
            "extra": "43506 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42410,
            "unit": "B/op",
            "extra": "43506 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43506 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 28173,
            "unit": "ns/op\t   42639 B/op\t      16 allocs/op",
            "extra": "40824 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 28173,
            "unit": "ns/op",
            "extra": "40824 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42639,
            "unit": "B/op",
            "extra": "40824 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "40824 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 28397,
            "unit": "ns/op\t   41432 B/op\t      16 allocs/op",
            "extra": "42297 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 28397,
            "unit": "ns/op",
            "extra": "42297 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41432,
            "unit": "B/op",
            "extra": "42297 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42297 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 27980,
            "unit": "ns/op\t   42354 B/op\t      16 allocs/op",
            "extra": "42426 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 27980,
            "unit": "ns/op",
            "extra": "42426 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42354,
            "unit": "B/op",
            "extra": "42426 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42426 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 52225,
            "unit": "ns/op\t   40199 B/op\t      16 allocs/op",
            "extra": "23001 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 52225,
            "unit": "ns/op",
            "extra": "23001 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 40199,
            "unit": "B/op",
            "extra": "23001 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "23001 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 71422,
            "unit": "ns/op\t   39208 B/op\t      16 allocs/op",
            "extra": "16911 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 71422,
            "unit": "ns/op",
            "extra": "16911 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 39208,
            "unit": "B/op",
            "extra": "16911 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16911 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 70696,
            "unit": "ns/op\t   38823 B/op\t      16 allocs/op",
            "extra": "16914 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 70696,
            "unit": "ns/op",
            "extra": "16914 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38823,
            "unit": "B/op",
            "extra": "16914 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16914 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 98923,
            "unit": "ns/op\t   37757 B/op\t      16 allocs/op",
            "extra": "12152 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 98923,
            "unit": "ns/op",
            "extra": "12152 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 37757,
            "unit": "B/op",
            "extra": "12152 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "12152 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "a7019828f651636b614d0ebec9402ebac2b1562c",
          "message": "chore(deps): update github/codeql-action action to v4.38.1 (#121)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-18T23:28:09Z",
          "url": "https://github.com/moov-io/cryptfs/commit/a7019828f651636b614d0ebec9402ebac2b1562c"
        },
        "date": 1789975828705,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 56911,
            "unit": "ns/op\t    4001 B/op\t      25 allocs/op",
            "extra": "20997 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 56911,
            "unit": "ns/op",
            "extra": "20997 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4001,
            "unit": "B/op",
            "extra": "20997 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "20997 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 54449,
            "unit": "ns/op\t   40039 B/op\t      16 allocs/op",
            "extra": "20606 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 54449,
            "unit": "ns/op",
            "extra": "20606 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 40039,
            "unit": "B/op",
            "extra": "20606 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "20606 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 20443,
            "unit": "ns/op\t   53610 B/op\t      16 allocs/op",
            "extra": "58264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 20443,
            "unit": "ns/op",
            "extra": "58264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53610,
            "unit": "B/op",
            "extra": "58264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "58264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 28375,
            "unit": "ns/op\t   41169 B/op\t      16 allocs/op",
            "extra": "43249 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 28375,
            "unit": "ns/op",
            "extra": "43249 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 41169,
            "unit": "B/op",
            "extra": "43249 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43249 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 26869,
            "unit": "ns/op\t   42775 B/op\t      16 allocs/op",
            "extra": "43813 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 26869,
            "unit": "ns/op",
            "extra": "43813 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42775,
            "unit": "B/op",
            "extra": "43813 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43813 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 26785,
            "unit": "ns/op\t   42182 B/op\t      16 allocs/op",
            "extra": "45438 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 26785,
            "unit": "ns/op",
            "extra": "45438 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42182,
            "unit": "B/op",
            "extra": "45438 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "45438 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 27569,
            "unit": "ns/op\t   41289 B/op\t      16 allocs/op",
            "extra": "42670 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 27569,
            "unit": "ns/op",
            "extra": "42670 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41289,
            "unit": "B/op",
            "extra": "42670 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42670 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 27163,
            "unit": "ns/op\t   42175 B/op\t      16 allocs/op",
            "extra": "44302 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 27163,
            "unit": "ns/op",
            "extra": "44302 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42175,
            "unit": "B/op",
            "extra": "44302 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "44302 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 51193,
            "unit": "ns/op\t   39716 B/op\t      16 allocs/op",
            "extra": "23364 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 51193,
            "unit": "ns/op",
            "extra": "23364 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 39716,
            "unit": "B/op",
            "extra": "23364 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "23364 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 70082,
            "unit": "ns/op\t   39042 B/op\t      16 allocs/op",
            "extra": "17104 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 70082,
            "unit": "ns/op",
            "extra": "17104 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 39042,
            "unit": "B/op",
            "extra": "17104 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "17104 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 70349,
            "unit": "ns/op\t   39871 B/op\t      16 allocs/op",
            "extra": "17125 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 70349,
            "unit": "ns/op",
            "extra": "17125 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 39871,
            "unit": "B/op",
            "extra": "17125 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "17125 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 97157,
            "unit": "ns/op\t   39300 B/op\t      16 allocs/op",
            "extra": "12366 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 97157,
            "unit": "ns/op",
            "extra": "12366 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 39300,
            "unit": "B/op",
            "extra": "12366 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "12366 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "a7019828f651636b614d0ebec9402ebac2b1562c",
          "message": "chore(deps): update github/codeql-action action to v4.38.1 (#121)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-18T23:28:09Z",
          "url": "https://github.com/moov-io/cryptfs/commit/a7019828f651636b614d0ebec9402ebac2b1562c"
        },
        "date": 1790060994180,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 56792,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "21085 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 56792,
            "unit": "ns/op",
            "extra": "21085 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "21085 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "21085 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 55313,
            "unit": "ns/op\t   39771 B/op\t      16 allocs/op",
            "extra": "20294 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 55313,
            "unit": "ns/op",
            "extra": "20294 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39771,
            "unit": "B/op",
            "extra": "20294 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "20294 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 19878,
            "unit": "ns/op\t   53363 B/op\t      16 allocs/op",
            "extra": "59224 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 19878,
            "unit": "ns/op",
            "extra": "59224 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53363,
            "unit": "B/op",
            "extra": "59224 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "59224 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 27516,
            "unit": "ns/op\t   40956 B/op\t      16 allocs/op",
            "extra": "42452 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 27516,
            "unit": "ns/op",
            "extra": "42452 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 40956,
            "unit": "B/op",
            "extra": "42452 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42452 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 28614,
            "unit": "ns/op\t   42331 B/op\t      16 allocs/op",
            "extra": "41785 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 28614,
            "unit": "ns/op",
            "extra": "41785 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42331,
            "unit": "B/op",
            "extra": "41785 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41785 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 28506,
            "unit": "ns/op\t   42865 B/op\t      16 allocs/op",
            "extra": "42298 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 28506,
            "unit": "ns/op",
            "extra": "42298 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42865,
            "unit": "B/op",
            "extra": "42298 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42298 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 28957,
            "unit": "ns/op\t   41764 B/op\t      16 allocs/op",
            "extra": "41438 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 28957,
            "unit": "ns/op",
            "extra": "41438 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41764,
            "unit": "B/op",
            "extra": "41438 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41438 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 28878,
            "unit": "ns/op\t   42112 B/op\t      16 allocs/op",
            "extra": "41310 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 28878,
            "unit": "ns/op",
            "extra": "41310 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42112,
            "unit": "B/op",
            "extra": "41310 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41310 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 53155,
            "unit": "ns/op\t   40560 B/op\t      16 allocs/op",
            "extra": "22634 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 53155,
            "unit": "ns/op",
            "extra": "22634 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 40560,
            "unit": "B/op",
            "extra": "22634 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22634 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 73354,
            "unit": "ns/op\t   39887 B/op\t      16 allocs/op",
            "extra": "16305 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 73354,
            "unit": "ns/op",
            "extra": "16305 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 39887,
            "unit": "B/op",
            "extra": "16305 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16305 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 72867,
            "unit": "ns/op\t   39163 B/op\t      16 allocs/op",
            "extra": "16459 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 72867,
            "unit": "ns/op",
            "extra": "16459 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 39163,
            "unit": "B/op",
            "extra": "16459 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16459 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 100884,
            "unit": "ns/op\t   38282 B/op\t      16 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 100884,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 38282,
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
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "a7019828f651636b614d0ebec9402ebac2b1562c",
          "message": "chore(deps): update github/codeql-action action to v4.38.1 (#121)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-18T23:28:09Z",
          "url": "https://github.com/moov-io/cryptfs/commit/a7019828f651636b614d0ebec9402ebac2b1562c"
        },
        "date": 1790147283985,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 60553,
            "unit": "ns/op\t    4001 B/op\t      25 allocs/op",
            "extra": "19287 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 60553,
            "unit": "ns/op",
            "extra": "19287 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4001,
            "unit": "B/op",
            "extra": "19287 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "19287 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 53943,
            "unit": "ns/op\t   39406 B/op\t      16 allocs/op",
            "extra": "20982 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 53943,
            "unit": "ns/op",
            "extra": "20982 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39406,
            "unit": "B/op",
            "extra": "20982 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "20982 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 20907,
            "unit": "ns/op\t   52995 B/op\t      16 allocs/op",
            "extra": "54678 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 20907,
            "unit": "ns/op",
            "extra": "54678 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 52995,
            "unit": "B/op",
            "extra": "54678 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "54678 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 27020,
            "unit": "ns/op\t   41324 B/op\t      16 allocs/op",
            "extra": "43567 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 27020,
            "unit": "ns/op",
            "extra": "43567 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 41324,
            "unit": "B/op",
            "extra": "43567 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43567 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 26947,
            "unit": "ns/op\t   42571 B/op\t      16 allocs/op",
            "extra": "43990 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 26947,
            "unit": "ns/op",
            "extra": "43990 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42571,
            "unit": "B/op",
            "extra": "43990 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43990 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 27334,
            "unit": "ns/op\t   42783 B/op\t      16 allocs/op",
            "extra": "43554 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 27334,
            "unit": "ns/op",
            "extra": "43554 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42783,
            "unit": "B/op",
            "extra": "43554 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43554 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 27945,
            "unit": "ns/op\t   41733 B/op\t      16 allocs/op",
            "extra": "42786 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 27945,
            "unit": "ns/op",
            "extra": "42786 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41733,
            "unit": "B/op",
            "extra": "42786 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42786 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 28682,
            "unit": "ns/op\t   42288 B/op\t      16 allocs/op",
            "extra": "42205 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 28682,
            "unit": "ns/op",
            "extra": "42205 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42288,
            "unit": "B/op",
            "extra": "42205 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42205 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 52584,
            "unit": "ns/op\t   39479 B/op\t      16 allocs/op",
            "extra": "22704 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 52584,
            "unit": "ns/op",
            "extra": "22704 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 39479,
            "unit": "B/op",
            "extra": "22704 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22704 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 75777,
            "unit": "ns/op\t   39558 B/op\t      16 allocs/op",
            "extra": "16768 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 75777,
            "unit": "ns/op",
            "extra": "16768 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 39558,
            "unit": "B/op",
            "extra": "16768 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16768 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 71653,
            "unit": "ns/op\t   38179 B/op\t      16 allocs/op",
            "extra": "16761 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 71653,
            "unit": "ns/op",
            "extra": "16761 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38179,
            "unit": "B/op",
            "extra": "16761 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16761 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 100954,
            "unit": "ns/op\t   38515 B/op\t      16 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 100954,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 38515,
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
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "9e749f6e23597cd0dcb658e4131a80c0b40da090",
          "message": "fix(deps): update module github.com/protonmail/go-crypto to v1.5.1 (#123)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-24T00:08:09Z",
          "url": "https://github.com/moov-io/cryptfs/commit/9e749f6e23597cd0dcb658e4131a80c0b40da090"
        },
        "date": 1790233348801,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 24196,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "48948 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 24196,
            "unit": "ns/op",
            "extra": "48948 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "48948 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "48948 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 42457,
            "unit": "ns/op\t   40528 B/op\t      16 allocs/op",
            "extra": "27955 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 42457,
            "unit": "ns/op",
            "extra": "27955 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 40528,
            "unit": "B/op",
            "extra": "27955 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "27955 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 16606,
            "unit": "ns/op\t   53972 B/op\t      16 allocs/op",
            "extra": "73762 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 16606,
            "unit": "ns/op",
            "extra": "73762 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53972,
            "unit": "B/op",
            "extra": "73762 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "73762 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 23440,
            "unit": "ns/op\t   41408 B/op\t      16 allocs/op",
            "extra": "52264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 23440,
            "unit": "ns/op",
            "extra": "52264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 41408,
            "unit": "B/op",
            "extra": "52264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "52264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 23271,
            "unit": "ns/op\t   42650 B/op\t      16 allocs/op",
            "extra": "52579 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 23271,
            "unit": "ns/op",
            "extra": "52579 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42650,
            "unit": "B/op",
            "extra": "52579 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "52579 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 23485,
            "unit": "ns/op\t   42492 B/op\t      16 allocs/op",
            "extra": "50628 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 23485,
            "unit": "ns/op",
            "extra": "50628 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42492,
            "unit": "B/op",
            "extra": "50628 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "50628 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 23394,
            "unit": "ns/op\t   41878 B/op\t      16 allocs/op",
            "extra": "50748 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 23394,
            "unit": "ns/op",
            "extra": "50748 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41878,
            "unit": "B/op",
            "extra": "50748 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "50748 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 23551,
            "unit": "ns/op\t   42418 B/op\t      16 allocs/op",
            "extra": "51710 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 23551,
            "unit": "ns/op",
            "extra": "51710 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42418,
            "unit": "B/op",
            "extra": "51710 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "51710 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 42734,
            "unit": "ns/op\t   40526 B/op\t      16 allocs/op",
            "extra": "28362 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 42734,
            "unit": "ns/op",
            "extra": "28362 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 40526,
            "unit": "B/op",
            "extra": "28362 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "28362 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 75666,
            "unit": "ns/op\t   38465 B/op\t      16 allocs/op",
            "extra": "15782 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 75666,
            "unit": "ns/op",
            "extra": "15782 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 38465,
            "unit": "B/op",
            "extra": "15782 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15782 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 76572,
            "unit": "ns/op\t   38716 B/op\t      16 allocs/op",
            "extra": "15584 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 76572,
            "unit": "ns/op",
            "extra": "15584 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38716,
            "unit": "B/op",
            "extra": "15584 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15584 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 96127,
            "unit": "ns/op\t   37159 B/op\t      16 allocs/op",
            "extra": "12435 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 96127,
            "unit": "ns/op",
            "extra": "12435 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 37159,
            "unit": "B/op",
            "extra": "12435 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "12435 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "f4c9af0ba2d691ac296ee794465798fd70c2aa0d",
          "message": "chore(deps): update github/codeql-action action to v4.38.2 (#124)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-24T19:35:40Z",
          "url": "https://github.com/moov-io/cryptfs/commit/f4c9af0ba2d691ac296ee794465798fd70c2aa0d"
        },
        "date": 1790319486386,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 58154,
            "unit": "ns/op\t    4001 B/op\t      25 allocs/op",
            "extra": "20328 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 58154,
            "unit": "ns/op",
            "extra": "20328 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4001,
            "unit": "B/op",
            "extra": "20328 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "20328 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 54078,
            "unit": "ns/op\t   39929 B/op\t      16 allocs/op",
            "extra": "21946 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 54078,
            "unit": "ns/op",
            "extra": "21946 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39929,
            "unit": "B/op",
            "extra": "21946 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "21946 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 19700,
            "unit": "ns/op\t   52804 B/op\t      16 allocs/op",
            "extra": "64636 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 19700,
            "unit": "ns/op",
            "extra": "64636 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 52804,
            "unit": "B/op",
            "extra": "64636 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "64636 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 30190,
            "unit": "ns/op\t   40862 B/op\t      16 allocs/op",
            "extra": "39513 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 30190,
            "unit": "ns/op",
            "extra": "39513 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 40862,
            "unit": "B/op",
            "extra": "39513 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "39513 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 28428,
            "unit": "ns/op\t   42254 B/op\t      16 allocs/op",
            "extra": "42088 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 28428,
            "unit": "ns/op",
            "extra": "42088 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42254,
            "unit": "B/op",
            "extra": "42088 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42088 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 28553,
            "unit": "ns/op\t   42582 B/op\t      16 allocs/op",
            "extra": "42153 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 28553,
            "unit": "ns/op",
            "extra": "42153 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42582,
            "unit": "B/op",
            "extra": "42153 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42153 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 29857,
            "unit": "ns/op\t   41749 B/op\t      16 allocs/op",
            "extra": "41889 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 29857,
            "unit": "ns/op",
            "extra": "41889 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41749,
            "unit": "B/op",
            "extra": "41889 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41889 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 29534,
            "unit": "ns/op\t   41987 B/op\t      16 allocs/op",
            "extra": "40154 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 29534,
            "unit": "ns/op",
            "extra": "40154 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 41987,
            "unit": "B/op",
            "extra": "40154 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "40154 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 53502,
            "unit": "ns/op\t   39628 B/op\t      16 allocs/op",
            "extra": "22546 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 53502,
            "unit": "ns/op",
            "extra": "22546 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 39628,
            "unit": "B/op",
            "extra": "22546 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22546 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 77436,
            "unit": "ns/op\t   38377 B/op\t      16 allocs/op",
            "extra": "15418 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 77436,
            "unit": "ns/op",
            "extra": "15418 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 38377,
            "unit": "B/op",
            "extra": "15418 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15418 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 75978,
            "unit": "ns/op\t   38163 B/op\t      16 allocs/op",
            "extra": "15733 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 75978,
            "unit": "ns/op",
            "extra": "15733 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38163,
            "unit": "B/op",
            "extra": "15733 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15733 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 101347,
            "unit": "ns/op\t   39155 B/op\t      16 allocs/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 101347,
            "unit": "ns/op",
            "extra": "10000 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 39155,
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
            "name": "Adam Shannon",
            "username": "adamdecaf",
            "email": "adamkshannon@gmail.com"
          },
          "id": "12d8b89745449a424f9af962d05a68f5b00c196d",
          "message": "chore: go mod tidy for Go 1.26\n\nCI make check fails with \"go: updates to go.mod needed\" until the go directive matches the runner toolchain.",
          "timestamp": "2026-09-25T14:45:53Z",
          "url": "https://github.com/moov-io/cryptfs/commit/12d8b89745449a424f9af962d05a68f5b00c196d"
        },
        "date": 1790405851506,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 22166,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "54254 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 22166,
            "unit": "ns/op",
            "extra": "54254 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "54254 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "54254 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 40887,
            "unit": "ns/op\t   39943 B/op\t      16 allocs/op",
            "extra": "29388 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 40887,
            "unit": "ns/op",
            "extra": "29388 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39943,
            "unit": "B/op",
            "extra": "29388 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "29388 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 16644,
            "unit": "ns/op\t   53976 B/op\t      16 allocs/op",
            "extra": "71892 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 16644,
            "unit": "ns/op",
            "extra": "71892 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53976,
            "unit": "B/op",
            "extra": "71892 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "71892 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 22974,
            "unit": "ns/op\t   41452 B/op\t      16 allocs/op",
            "extra": "52179 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 22974,
            "unit": "ns/op",
            "extra": "52179 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 41452,
            "unit": "B/op",
            "extra": "52179 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "52179 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 22401,
            "unit": "ns/op\t   42566 B/op\t      16 allocs/op",
            "extra": "54134 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 22401,
            "unit": "ns/op",
            "extra": "54134 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42566,
            "unit": "B/op",
            "extra": "54134 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "54134 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 22945,
            "unit": "ns/op\t   42502 B/op\t      16 allocs/op",
            "extra": "54033 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 22945,
            "unit": "ns/op",
            "extra": "54033 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42502,
            "unit": "B/op",
            "extra": "54033 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "54033 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 23466,
            "unit": "ns/op\t   41721 B/op\t      16 allocs/op",
            "extra": "51115 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 23466,
            "unit": "ns/op",
            "extra": "51115 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41721,
            "unit": "B/op",
            "extra": "51115 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "51115 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 23822,
            "unit": "ns/op\t   41488 B/op\t      16 allocs/op",
            "extra": "48638 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 23822,
            "unit": "ns/op",
            "extra": "48638 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 41488,
            "unit": "B/op",
            "extra": "48638 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "48638 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 41023,
            "unit": "ns/op\t   40763 B/op\t      16 allocs/op",
            "extra": "29416 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 41023,
            "unit": "ns/op",
            "extra": "29416 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 40763,
            "unit": "B/op",
            "extra": "29416 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "29416 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 71849,
            "unit": "ns/op\t   37744 B/op\t      16 allocs/op",
            "extra": "16808 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 71849,
            "unit": "ns/op",
            "extra": "16808 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 37744,
            "unit": "B/op",
            "extra": "16808 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16808 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 71498,
            "unit": "ns/op\t   37502 B/op\t      16 allocs/op",
            "extra": "16864 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 71498,
            "unit": "ns/op",
            "extra": "16864 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 37502,
            "unit": "B/op",
            "extra": "16864 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16864 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 92280,
            "unit": "ns/op\t   37058 B/op\t      16 allocs/op",
            "extra": "12996 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 92280,
            "unit": "ns/op",
            "extra": "12996 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 37058,
            "unit": "B/op",
            "extra": "12996 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "12996 times\n4 procs"
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
            "name": "Adam Shannon",
            "username": "adamdecaf",
            "email": "adamkshannon@gmail.com"
          },
          "id": "12d8b89745449a424f9af962d05a68f5b00c196d",
          "message": "chore: go mod tidy for Go 1.26\n\nCI make check fails with \"go: updates to go.mod needed\" until the go directive matches the runner toolchain.",
          "timestamp": "2026-09-25T14:45:53Z",
          "url": "https://github.com/moov-io/cryptfs/commit/12d8b89745449a424f9af962d05a68f5b00c196d"
        },
        "date": 1790494018105,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 61581,
            "unit": "ns/op\t    4001 B/op\t      25 allocs/op",
            "extra": "19408 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 61581,
            "unit": "ns/op",
            "extra": "19408 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4001,
            "unit": "B/op",
            "extra": "19408 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "19408 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 56698,
            "unit": "ns/op\t   39765 B/op\t      16 allocs/op",
            "extra": "19903 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 56698,
            "unit": "ns/op",
            "extra": "19903 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39765,
            "unit": "B/op",
            "extra": "19903 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "19903 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 21970,
            "unit": "ns/op\t   53405 B/op\t      16 allocs/op",
            "extra": "52842 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 21970,
            "unit": "ns/op",
            "extra": "52842 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53405,
            "unit": "B/op",
            "extra": "52842 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "52842 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 30337,
            "unit": "ns/op\t   40915 B/op\t      16 allocs/op",
            "extra": "39325 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 30337,
            "unit": "ns/op",
            "extra": "39325 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 40915,
            "unit": "B/op",
            "extra": "39325 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "39325 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 28722,
            "unit": "ns/op\t   42586 B/op\t      16 allocs/op",
            "extra": "42021 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 28722,
            "unit": "ns/op",
            "extra": "42021 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42586,
            "unit": "B/op",
            "extra": "42021 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42021 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 27985,
            "unit": "ns/op\t   42192 B/op\t      16 allocs/op",
            "extra": "43790 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 27985,
            "unit": "ns/op",
            "extra": "43790 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42192,
            "unit": "B/op",
            "extra": "43790 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43790 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 29322,
            "unit": "ns/op\t   41718 B/op\t      16 allocs/op",
            "extra": "39686 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 29322,
            "unit": "ns/op",
            "extra": "39686 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41718,
            "unit": "B/op",
            "extra": "39686 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "39686 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 29716,
            "unit": "ns/op\t   41915 B/op\t      16 allocs/op",
            "extra": "40719 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 29716,
            "unit": "ns/op",
            "extra": "40719 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 41915,
            "unit": "B/op",
            "extra": "40719 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "40719 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 52523,
            "unit": "ns/op\t   39103 B/op\t      16 allocs/op",
            "extra": "22648 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 52523,
            "unit": "ns/op",
            "extra": "22648 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 39103,
            "unit": "B/op",
            "extra": "22648 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22648 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 75151,
            "unit": "ns/op\t   38657 B/op\t      16 allocs/op",
            "extra": "16341 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 75151,
            "unit": "ns/op",
            "extra": "16341 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 38657,
            "unit": "B/op",
            "extra": "16341 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16341 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 74040,
            "unit": "ns/op\t   38261 B/op\t      16 allocs/op",
            "extra": "15956 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 74040,
            "unit": "ns/op",
            "extra": "15956 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38261,
            "unit": "B/op",
            "extra": "15956 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15956 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 98736,
            "unit": "ns/op\t   38546 B/op\t      16 allocs/op",
            "extra": "12313 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 98736,
            "unit": "ns/op",
            "extra": "12313 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 38546,
            "unit": "B/op",
            "extra": "12313 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "12313 times\n4 procs"
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
            "name": "Adam Shannon",
            "username": "adamdecaf",
            "email": "adamkshannon@gmail.com"
          },
          "id": "12d8b89745449a424f9af962d05a68f5b00c196d",
          "message": "chore: go mod tidy for Go 1.26\n\nCI make check fails with \"go: updates to go.mod needed\" until the go directive matches the runner toolchain.",
          "timestamp": "2026-09-25T14:45:53Z",
          "url": "https://github.com/moov-io/cryptfs/commit/12d8b89745449a424f9af962d05a68f5b00c196d"
        },
        "date": 1790582691026,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 60431,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "18987 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 60431,
            "unit": "ns/op",
            "extra": "18987 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "18987 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "18987 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 53090,
            "unit": "ns/op\t   40476 B/op\t      16 allocs/op",
            "extra": "22327 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 53090,
            "unit": "ns/op",
            "extra": "22327 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 40476,
            "unit": "B/op",
            "extra": "22327 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22327 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 18886,
            "unit": "ns/op\t   53263 B/op\t      16 allocs/op",
            "extra": "62649 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 18886,
            "unit": "ns/op",
            "extra": "62649 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53263,
            "unit": "B/op",
            "extra": "62649 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "62649 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 30532,
            "unit": "ns/op\t   40515 B/op\t      16 allocs/op",
            "extra": "39908 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 30532,
            "unit": "ns/op",
            "extra": "39908 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 40515,
            "unit": "B/op",
            "extra": "39908 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "39908 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 28107,
            "unit": "ns/op\t   42650 B/op\t      16 allocs/op",
            "extra": "42970 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 28107,
            "unit": "ns/op",
            "extra": "42970 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42650,
            "unit": "B/op",
            "extra": "42970 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42970 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 28482,
            "unit": "ns/op\t   42742 B/op\t      16 allocs/op",
            "extra": "41866 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 28482,
            "unit": "ns/op",
            "extra": "41866 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42742,
            "unit": "B/op",
            "extra": "41866 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41866 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 30289,
            "unit": "ns/op\t   41141 B/op\t      16 allocs/op",
            "extra": "42447 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 30289,
            "unit": "ns/op",
            "extra": "42447 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41141,
            "unit": "B/op",
            "extra": "42447 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "42447 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 29332,
            "unit": "ns/op\t   41657 B/op\t      16 allocs/op",
            "extra": "39735 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 29332,
            "unit": "ns/op",
            "extra": "39735 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 41657,
            "unit": "B/op",
            "extra": "39735 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "39735 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 53343,
            "unit": "ns/op\t   40000 B/op\t      16 allocs/op",
            "extra": "22314 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 53343,
            "unit": "ns/op",
            "extra": "22314 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 40000,
            "unit": "B/op",
            "extra": "22314 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22314 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 75392,
            "unit": "ns/op\t   38579 B/op\t      16 allocs/op",
            "extra": "15912 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 75392,
            "unit": "ns/op",
            "extra": "15912 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 38579,
            "unit": "B/op",
            "extra": "15912 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15912 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 76041,
            "unit": "ns/op\t   38896 B/op\t      16 allocs/op",
            "extra": "15757 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 76041,
            "unit": "ns/op",
            "extra": "15757 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38896,
            "unit": "B/op",
            "extra": "15757 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15757 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 99687,
            "unit": "ns/op\t   38549 B/op\t      16 allocs/op",
            "extra": "12096 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 99687,
            "unit": "ns/op",
            "extra": "12096 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 38549,
            "unit": "B/op",
            "extra": "12096 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "12096 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "809c8f989bda9f9cfeafa6c867601fd9d68cc23f",
          "message": "fix(deps): update module github.com/protonmail/go-crypto to v1.5.2 (#126)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-28T21:31:06Z",
          "url": "https://github.com/moov-io/cryptfs/commit/809c8f989bda9f9cfeafa6c867601fd9d68cc23f"
        },
        "date": 1790667931085,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 43143,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "27902 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 43143,
            "unit": "ns/op",
            "extra": "27902 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "27902 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "27902 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 38501,
            "unit": "ns/op\t   38506 B/op\t      16 allocs/op",
            "extra": "31240 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 38501,
            "unit": "ns/op",
            "extra": "31240 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 38506,
            "unit": "B/op",
            "extra": "31240 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "31240 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 13442,
            "unit": "ns/op\t   52882 B/op\t      16 allocs/op",
            "extra": "89778 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 13442,
            "unit": "ns/op",
            "extra": "89778 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 52882,
            "unit": "B/op",
            "extra": "89778 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "89778 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 20731,
            "unit": "ns/op\t   41217 B/op\t      16 allocs/op",
            "extra": "57910 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 20731,
            "unit": "ns/op",
            "extra": "57910 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 41217,
            "unit": "B/op",
            "extra": "57910 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "57910 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 20884,
            "unit": "ns/op\t   42553 B/op\t      16 allocs/op",
            "extra": "57193 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 20884,
            "unit": "ns/op",
            "extra": "57193 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42553,
            "unit": "B/op",
            "extra": "57193 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "57193 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 21070,
            "unit": "ns/op\t   42758 B/op\t      16 allocs/op",
            "extra": "55879 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 21070,
            "unit": "ns/op",
            "extra": "55879 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42758,
            "unit": "B/op",
            "extra": "55879 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "55879 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 21466,
            "unit": "ns/op\t   41132 B/op\t      16 allocs/op",
            "extra": "58788 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 21466,
            "unit": "ns/op",
            "extra": "58788 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41132,
            "unit": "B/op",
            "extra": "58788 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "58788 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 21053,
            "unit": "ns/op\t   42473 B/op\t      16 allocs/op",
            "extra": "56360 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 21053,
            "unit": "ns/op",
            "extra": "56360 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42473,
            "unit": "B/op",
            "extra": "56360 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "56360 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 38406,
            "unit": "ns/op\t   38987 B/op\t      16 allocs/op",
            "extra": "31308 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 38406,
            "unit": "ns/op",
            "extra": "31308 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 38987,
            "unit": "B/op",
            "extra": "31308 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "31308 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 55163,
            "unit": "ns/op\t   38942 B/op\t      16 allocs/op",
            "extra": "21825 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 55163,
            "unit": "ns/op",
            "extra": "21825 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 38942,
            "unit": "B/op",
            "extra": "21825 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "21825 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 55953,
            "unit": "ns/op\t   40087 B/op\t      16 allocs/op",
            "extra": "21322 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 55953,
            "unit": "ns/op",
            "extra": "21322 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 40087,
            "unit": "B/op",
            "extra": "21322 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "21322 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 74120,
            "unit": "ns/op\t   34893 B/op\t      16 allocs/op",
            "extra": "16042 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 74120,
            "unit": "ns/op",
            "extra": "16042 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 34893,
            "unit": "B/op",
            "extra": "16042 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16042 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "809c8f989bda9f9cfeafa6c867601fd9d68cc23f",
          "message": "fix(deps): update module github.com/protonmail/go-crypto to v1.5.2 (#126)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-28T21:31:06Z",
          "url": "https://github.com/moov-io/cryptfs/commit/809c8f989bda9f9cfeafa6c867601fd9d68cc23f"
        },
        "date": 1790754527677,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 46559,
            "unit": "ns/op\t    4001 B/op\t      25 allocs/op",
            "extra": "27480 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 46559,
            "unit": "ns/op",
            "extra": "27480 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4001,
            "unit": "B/op",
            "extra": "27480 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "27480 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 40105,
            "unit": "ns/op\t   39998 B/op\t      16 allocs/op",
            "extra": "29260 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 40105,
            "unit": "ns/op",
            "extra": "29260 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39998,
            "unit": "B/op",
            "extra": "29260 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "29260 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 14639,
            "unit": "ns/op\t   52786 B/op\t      16 allocs/op",
            "extra": "71196 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 14639,
            "unit": "ns/op",
            "extra": "71196 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 52786,
            "unit": "B/op",
            "extra": "71196 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "71196 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 21013,
            "unit": "ns/op\t   40682 B/op\t      16 allocs/op",
            "extra": "57541 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 21013,
            "unit": "ns/op",
            "extra": "57541 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 40682,
            "unit": "B/op",
            "extra": "57541 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "57541 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 20784,
            "unit": "ns/op\t   42757 B/op\t      16 allocs/op",
            "extra": "57200 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 20784,
            "unit": "ns/op",
            "extra": "57200 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42757,
            "unit": "B/op",
            "extra": "57200 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "57200 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 20584,
            "unit": "ns/op\t   42506 B/op\t      16 allocs/op",
            "extra": "57355 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 20584,
            "unit": "ns/op",
            "extra": "57355 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42506,
            "unit": "B/op",
            "extra": "57355 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "57355 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 21659,
            "unit": "ns/op\t   41331 B/op\t      16 allocs/op",
            "extra": "56146 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 21659,
            "unit": "ns/op",
            "extra": "56146 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41331,
            "unit": "B/op",
            "extra": "56146 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "56146 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 21218,
            "unit": "ns/op\t   41962 B/op\t      16 allocs/op",
            "extra": "57051 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 21218,
            "unit": "ns/op",
            "extra": "57051 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 41962,
            "unit": "B/op",
            "extra": "57051 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "57051 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 38990,
            "unit": "ns/op\t   39775 B/op\t      16 allocs/op",
            "extra": "30178 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 38990,
            "unit": "ns/op",
            "extra": "30178 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 39775,
            "unit": "B/op",
            "extra": "30178 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "30178 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 57142,
            "unit": "ns/op\t   39740 B/op\t      16 allocs/op",
            "extra": "20977 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 57142,
            "unit": "ns/op",
            "extra": "20977 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 39740,
            "unit": "B/op",
            "extra": "20977 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "20977 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 56818,
            "unit": "ns/op\t   39220 B/op\t      16 allocs/op",
            "extra": "21448 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 56818,
            "unit": "ns/op",
            "extra": "21448 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 39220,
            "unit": "B/op",
            "extra": "21448 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "21448 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 78851,
            "unit": "ns/op\t   36572 B/op\t      16 allocs/op",
            "extra": "15207 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 78851,
            "unit": "ns/op",
            "extra": "15207 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 36572,
            "unit": "B/op",
            "extra": "15207 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15207 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "809c8f989bda9f9cfeafa6c867601fd9d68cc23f",
          "message": "fix(deps): update module github.com/protonmail/go-crypto to v1.5.2 (#126)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-28T21:31:06Z",
          "url": "https://github.com/moov-io/cryptfs/commit/809c8f989bda9f9cfeafa6c867601fd9d68cc23f"
        },
        "date": 1790842086266,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 27524,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "52366 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 27524,
            "unit": "ns/op",
            "extra": "52366 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "52366 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "52366 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 43260,
            "unit": "ns/op\t   39969 B/op\t      16 allocs/op",
            "extra": "27217 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 43260,
            "unit": "ns/op",
            "extra": "27217 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39969,
            "unit": "B/op",
            "extra": "27217 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "27217 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 17830,
            "unit": "ns/op\t   53676 B/op\t      16 allocs/op",
            "extra": "61328 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 17830,
            "unit": "ns/op",
            "extra": "61328 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53676,
            "unit": "B/op",
            "extra": "61328 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "61328 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 23792,
            "unit": "ns/op\t   41543 B/op\t      16 allocs/op",
            "extra": "51025 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 23792,
            "unit": "ns/op",
            "extra": "51025 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 41543,
            "unit": "B/op",
            "extra": "51025 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "51025 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 23467,
            "unit": "ns/op\t   43359 B/op\t      16 allocs/op",
            "extra": "51387 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 23467,
            "unit": "ns/op",
            "extra": "51387 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 43359,
            "unit": "B/op",
            "extra": "51387 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "51387 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 22841,
            "unit": "ns/op\t   42851 B/op\t      16 allocs/op",
            "extra": "50817 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 22841,
            "unit": "ns/op",
            "extra": "50817 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42851,
            "unit": "B/op",
            "extra": "50817 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "50817 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 24320,
            "unit": "ns/op\t   42205 B/op\t      16 allocs/op",
            "extra": "48537 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 24320,
            "unit": "ns/op",
            "extra": "48537 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 42205,
            "unit": "B/op",
            "extra": "48537 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "48537 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 23703,
            "unit": "ns/op\t   42097 B/op\t      16 allocs/op",
            "extra": "50606 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 23703,
            "unit": "ns/op",
            "extra": "50606 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42097,
            "unit": "B/op",
            "extra": "50606 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "50606 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 42517,
            "unit": "ns/op\t   41423 B/op\t      16 allocs/op",
            "extra": "27944 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 42517,
            "unit": "ns/op",
            "extra": "27944 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 41423,
            "unit": "B/op",
            "extra": "27944 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "27944 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 75362,
            "unit": "ns/op\t   37424 B/op\t      16 allocs/op",
            "extra": "15907 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 75362,
            "unit": "ns/op",
            "extra": "15907 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 37424,
            "unit": "B/op",
            "extra": "15907 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15907 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 75498,
            "unit": "ns/op\t   38369 B/op\t      16 allocs/op",
            "extra": "15782 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 75498,
            "unit": "ns/op",
            "extra": "15782 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38369,
            "unit": "B/op",
            "extra": "15782 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15782 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 95839,
            "unit": "ns/op\t   36636 B/op\t      16 allocs/op",
            "extra": "12553 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 95839,
            "unit": "ns/op",
            "extra": "12553 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 36636,
            "unit": "B/op",
            "extra": "12553 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "12553 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "809c8f989bda9f9cfeafa6c867601fd9d68cc23f",
          "message": "fix(deps): update module github.com/protonmail/go-crypto to v1.5.2 (#126)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-28T21:31:06Z",
          "url": "https://github.com/moov-io/cryptfs/commit/809c8f989bda9f9cfeafa6c867601fd9d68cc23f"
        },
        "date": 1790927380911,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 64719,
            "unit": "ns/op\t    4001 B/op\t      25 allocs/op",
            "extra": "16956 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 64719,
            "unit": "ns/op",
            "extra": "16956 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4001,
            "unit": "B/op",
            "extra": "16956 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "16956 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 52480,
            "unit": "ns/op\t   39660 B/op\t      16 allocs/op",
            "extra": "23047 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 52480,
            "unit": "ns/op",
            "extra": "23047 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39660,
            "unit": "B/op",
            "extra": "23047 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "23047 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 19921,
            "unit": "ns/op\t   53542 B/op\t      16 allocs/op",
            "extra": "54822 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 19921,
            "unit": "ns/op",
            "extra": "54822 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53542,
            "unit": "B/op",
            "extra": "54822 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "54822 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 31615,
            "unit": "ns/op\t   40528 B/op\t      16 allocs/op",
            "extra": "40506 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 31615,
            "unit": "ns/op",
            "extra": "40506 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 40528,
            "unit": "B/op",
            "extra": "40506 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "40506 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 28453,
            "unit": "ns/op\t   42175 B/op\t      16 allocs/op",
            "extra": "40980 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 28453,
            "unit": "ns/op",
            "extra": "40980 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42175,
            "unit": "B/op",
            "extra": "40980 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "40980 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 28442,
            "unit": "ns/op\t   42275 B/op\t      16 allocs/op",
            "extra": "41989 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 28442,
            "unit": "ns/op",
            "extra": "41989 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42275,
            "unit": "B/op",
            "extra": "41989 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41989 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 30066,
            "unit": "ns/op\t   41063 B/op\t      16 allocs/op",
            "extra": "41175 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 30066,
            "unit": "ns/op",
            "extra": "41175 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41063,
            "unit": "B/op",
            "extra": "41175 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41175 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 28362,
            "unit": "ns/op\t   42187 B/op\t      16 allocs/op",
            "extra": "41550 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 28362,
            "unit": "ns/op",
            "extra": "41550 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42187,
            "unit": "B/op",
            "extra": "41550 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41550 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 52353,
            "unit": "ns/op\t   40079 B/op\t      16 allocs/op",
            "extra": "22516 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 52353,
            "unit": "ns/op",
            "extra": "22516 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 40079,
            "unit": "B/op",
            "extra": "22516 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22516 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 73670,
            "unit": "ns/op\t   38335 B/op\t      16 allocs/op",
            "extra": "16365 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 73670,
            "unit": "ns/op",
            "extra": "16365 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 38335,
            "unit": "B/op",
            "extra": "16365 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16365 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 73552,
            "unit": "ns/op\t   39457 B/op\t      16 allocs/op",
            "extra": "16400 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 73552,
            "unit": "ns/op",
            "extra": "16400 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 39457,
            "unit": "B/op",
            "extra": "16400 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "16400 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 97762,
            "unit": "ns/op\t   38208 B/op\t      16 allocs/op",
            "extra": "12232 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 97762,
            "unit": "ns/op",
            "extra": "12232 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 38208,
            "unit": "B/op",
            "extra": "12232 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "12232 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "809c8f989bda9f9cfeafa6c867601fd9d68cc23f",
          "message": "fix(deps): update module github.com/protonmail/go-crypto to v1.5.2 (#126)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-28T21:31:06Z",
          "url": "https://github.com/moov-io/cryptfs/commit/809c8f989bda9f9cfeafa6c867601fd9d68cc23f"
        },
        "date": 1791012327312,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 57824,
            "unit": "ns/op\t    4001 B/op\t      25 allocs/op",
            "extra": "20570 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 57824,
            "unit": "ns/op",
            "extra": "20570 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4001,
            "unit": "B/op",
            "extra": "20570 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "20570 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 55872,
            "unit": "ns/op\t   39768 B/op\t      16 allocs/op",
            "extra": "22803 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 55872,
            "unit": "ns/op",
            "extra": "22803 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39768,
            "unit": "B/op",
            "extra": "22803 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22803 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 23377,
            "unit": "ns/op\t   53129 B/op\t      16 allocs/op",
            "extra": "50667 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 23377,
            "unit": "ns/op",
            "extra": "50667 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53129,
            "unit": "B/op",
            "extra": "50667 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "50667 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 30832,
            "unit": "ns/op\t   40736 B/op\t      16 allocs/op",
            "extra": "40131 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 30832,
            "unit": "ns/op",
            "extra": "40131 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 40736,
            "unit": "B/op",
            "extra": "40131 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "40131 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 28221,
            "unit": "ns/op\t   42641 B/op\t      16 allocs/op",
            "extra": "43317 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 28221,
            "unit": "ns/op",
            "extra": "43317 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42641,
            "unit": "B/op",
            "extra": "43317 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43317 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 28460,
            "unit": "ns/op\t   42606 B/op\t      16 allocs/op",
            "extra": "43016 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 28460,
            "unit": "ns/op",
            "extra": "43016 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42606,
            "unit": "B/op",
            "extra": "43016 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43016 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 29072,
            "unit": "ns/op\t   41560 B/op\t      16 allocs/op",
            "extra": "40755 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 29072,
            "unit": "ns/op",
            "extra": "40755 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41560,
            "unit": "B/op",
            "extra": "40755 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "40755 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 28770,
            "unit": "ns/op\t   42056 B/op\t      16 allocs/op",
            "extra": "40878 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 28770,
            "unit": "ns/op",
            "extra": "40878 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42056,
            "unit": "B/op",
            "extra": "40878 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "40878 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 53029,
            "unit": "ns/op\t   40449 B/op\t      16 allocs/op",
            "extra": "22698 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 53029,
            "unit": "ns/op",
            "extra": "22698 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 40449,
            "unit": "B/op",
            "extra": "22698 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "22698 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 75353,
            "unit": "ns/op\t   38324 B/op\t      16 allocs/op",
            "extra": "15932 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 75353,
            "unit": "ns/op",
            "extra": "15932 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 38324,
            "unit": "B/op",
            "extra": "15932 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15932 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 75297,
            "unit": "ns/op\t   38726 B/op\t      16 allocs/op",
            "extra": "15866 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 75297,
            "unit": "ns/op",
            "extra": "15866 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38726,
            "unit": "B/op",
            "extra": "15866 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15866 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 98956,
            "unit": "ns/op\t   38711 B/op\t      16 allocs/op",
            "extra": "12098 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 98956,
            "unit": "ns/op",
            "extra": "12098 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 38711,
            "unit": "B/op",
            "extra": "12098 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "12098 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "809c8f989bda9f9cfeafa6c867601fd9d68cc23f",
          "message": "fix(deps): update module github.com/protonmail/go-crypto to v1.5.2 (#126)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-28T21:31:06Z",
          "url": "https://github.com/moov-io/cryptfs/commit/809c8f989bda9f9cfeafa6c867601fd9d68cc23f"
        },
        "date": 1791099535794,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 47142,
            "unit": "ns/op\t    4001 B/op\t      25 allocs/op",
            "extra": "23202 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 47142,
            "unit": "ns/op",
            "extra": "23202 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4001,
            "unit": "B/op",
            "extra": "23202 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "23202 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 39522,
            "unit": "ns/op\t   39977 B/op\t      16 allocs/op",
            "extra": "29806 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 39522,
            "unit": "ns/op",
            "extra": "29806 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39977,
            "unit": "B/op",
            "extra": "29806 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "29806 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 14351,
            "unit": "ns/op\t   53032 B/op\t      16 allocs/op",
            "extra": "83826 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 14351,
            "unit": "ns/op",
            "extra": "83826 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53032,
            "unit": "B/op",
            "extra": "83826 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "83826 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 21017,
            "unit": "ns/op\t   40842 B/op\t      16 allocs/op",
            "extra": "56264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 21017,
            "unit": "ns/op",
            "extra": "56264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 40842,
            "unit": "B/op",
            "extra": "56264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "56264 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 20364,
            "unit": "ns/op\t   42718 B/op\t      16 allocs/op",
            "extra": "57559 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 20364,
            "unit": "ns/op",
            "extra": "57559 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42718,
            "unit": "B/op",
            "extra": "57559 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "57559 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 20657,
            "unit": "ns/op\t   42497 B/op\t      16 allocs/op",
            "extra": "58267 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 20657,
            "unit": "ns/op",
            "extra": "58267 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42497,
            "unit": "B/op",
            "extra": "58267 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "58267 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 21099,
            "unit": "ns/op\t   41993 B/op\t      16 allocs/op",
            "extra": "57421 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 21099,
            "unit": "ns/op",
            "extra": "57421 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41993,
            "unit": "B/op",
            "extra": "57421 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "57421 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 21301,
            "unit": "ns/op\t   41906 B/op\t      16 allocs/op",
            "extra": "56089 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 21301,
            "unit": "ns/op",
            "extra": "56089 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 41906,
            "unit": "B/op",
            "extra": "56089 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "56089 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 42275,
            "unit": "ns/op\t   39398 B/op\t      16 allocs/op",
            "extra": "27910 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 42275,
            "unit": "ns/op",
            "extra": "27910 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 39398,
            "unit": "B/op",
            "extra": "27910 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "27910 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 55200,
            "unit": "ns/op\t   38344 B/op\t      16 allocs/op",
            "extra": "21669 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 55200,
            "unit": "ns/op",
            "extra": "21669 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 38344,
            "unit": "B/op",
            "extra": "21669 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "21669 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 55868,
            "unit": "ns/op\t   39079 B/op\t      16 allocs/op",
            "extra": "21722 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 55868,
            "unit": "ns/op",
            "extra": "21722 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 39079,
            "unit": "B/op",
            "extra": "21722 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "21722 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 75295,
            "unit": "ns/op\t   37009 B/op\t      16 allocs/op",
            "extra": "15871 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 75295,
            "unit": "ns/op",
            "extra": "15871 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 37009,
            "unit": "B/op",
            "extra": "15871 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15871 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "809c8f989bda9f9cfeafa6c867601fd9d68cc23f",
          "message": "fix(deps): update module github.com/protonmail/go-crypto to v1.5.2 (#126)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-28T21:31:06Z",
          "url": "https://github.com/moov-io/cryptfs/commit/809c8f989bda9f9cfeafa6c867601fd9d68cc23f"
        },
        "date": 1791187487056,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 39755,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "29809 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 39755,
            "unit": "ns/op",
            "extra": "29809 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "29809 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "29809 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 29578,
            "unit": "ns/op\t   39013 B/op\t      16 allocs/op",
            "extra": "41792 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 29578,
            "unit": "ns/op",
            "extra": "41792 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 39013,
            "unit": "B/op",
            "extra": "41792 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "41792 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 10303,
            "unit": "ns/op\t   52033 B/op\t      16 allocs/op",
            "extra": "107492 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 10303,
            "unit": "ns/op",
            "extra": "107492 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 52033,
            "unit": "B/op",
            "extra": "107492 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "107492 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 15352,
            "unit": "ns/op\t   40177 B/op\t      16 allocs/op",
            "extra": "78096 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 15352,
            "unit": "ns/op",
            "extra": "78096 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 40177,
            "unit": "B/op",
            "extra": "78096 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "78096 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 15488,
            "unit": "ns/op\t   42237 B/op\t      16 allocs/op",
            "extra": "79471 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 15488,
            "unit": "ns/op",
            "extra": "79471 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42237,
            "unit": "B/op",
            "extra": "79471 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "79471 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 16182,
            "unit": "ns/op\t   41469 B/op\t      16 allocs/op",
            "extra": "75622 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 16182,
            "unit": "ns/op",
            "extra": "75622 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 41469,
            "unit": "B/op",
            "extra": "75622 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "75622 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 15740,
            "unit": "ns/op\t   40836 B/op\t      16 allocs/op",
            "extra": "75226 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 15740,
            "unit": "ns/op",
            "extra": "75226 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 40836,
            "unit": "B/op",
            "extra": "75226 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "75226 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 15055,
            "unit": "ns/op\t   41261 B/op\t      16 allocs/op",
            "extra": "80155 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 15055,
            "unit": "ns/op",
            "extra": "80155 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 41261,
            "unit": "B/op",
            "extra": "80155 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "80155 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 28256,
            "unit": "ns/op\t   38639 B/op\t      16 allocs/op",
            "extra": "43256 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 28256,
            "unit": "ns/op",
            "extra": "43256 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 38639,
            "unit": "B/op",
            "extra": "43256 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "43256 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 38399,
            "unit": "ns/op\t   38325 B/op\t      16 allocs/op",
            "extra": "31976 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 38399,
            "unit": "ns/op",
            "extra": "31976 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 38325,
            "unit": "B/op",
            "extra": "31976 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "31976 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 38406,
            "unit": "ns/op\t   38380 B/op\t      16 allocs/op",
            "extra": "30279 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 38406,
            "unit": "ns/op",
            "extra": "30279 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 38380,
            "unit": "B/op",
            "extra": "30279 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "30279 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 54781,
            "unit": "ns/op\t   38831 B/op\t      16 allocs/op",
            "extra": "21795 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 54781,
            "unit": "ns/op",
            "extra": "21795 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 38831,
            "unit": "B/op",
            "extra": "21795 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "21795 times\n4 procs"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "renovate[bot]",
            "username": "renovate[bot]",
            "email": "29139614+renovate[bot]@users.noreply.github.com"
          },
          "committer": {
            "name": "GitHub",
            "username": "web-flow",
            "email": "noreply@github.com"
          },
          "id": "809c8f989bda9f9cfeafa6c867601fd9d68cc23f",
          "message": "fix(deps): update module github.com/protonmail/go-crypto to v1.5.2 (#126)\n\nCo-authored-by: renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>",
          "timestamp": "2026-09-28T21:31:06Z",
          "url": "https://github.com/moov-io/cryptfs/commit/809c8f989bda9f9cfeafa6c867601fd9d68cc23f"
        },
        "date": 1791275140147,
        "tool": "go",
        "benches": [
          {
            "name": "BenchmarkCryptfs__AES",
            "value": 19726,
            "unit": "ns/op\t    4000 B/op\t      25 allocs/op",
            "extra": "59779 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - ns/op",
            "value": 19726,
            "unit": "ns/op",
            "extra": "59779 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - B/op",
            "value": 4000,
            "unit": "B/op",
            "extra": "59779 times\n4 procs"
          },
          {
            "name": "BenchmarkCryptfs__AES - allocs/op",
            "value": 25,
            "unit": "allocs/op",
            "extra": "59779 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1",
            "value": 36004,
            "unit": "ns/op\t   40803 B/op\t      16 allocs/op",
            "extra": "33728 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - ns/op",
            "value": 36004,
            "unit": "ns/op",
            "extra": "33728 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - B/op",
            "value": 40803,
            "unit": "B/op",
            "extra": "33728 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_-1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "33728 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0",
            "value": 15607,
            "unit": "ns/op\t   53309 B/op\t      16 allocs/op",
            "extra": "70030 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - ns/op",
            "value": 15607,
            "unit": "ns/op",
            "extra": "70030 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - B/op",
            "value": 53309,
            "unit": "B/op",
            "extra": "70030 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_0 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "70030 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1",
            "value": 21982,
            "unit": "ns/op\t   41159 B/op\t      16 allocs/op",
            "extra": "56544 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - ns/op",
            "value": 21982,
            "unit": "ns/op",
            "extra": "56544 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - B/op",
            "value": 41159,
            "unit": "B/op",
            "extra": "56544 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_1 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "56544 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2",
            "value": 20266,
            "unit": "ns/op\t   42356 B/op\t      16 allocs/op",
            "extra": "56151 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - ns/op",
            "value": 20266,
            "unit": "ns/op",
            "extra": "56151 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - B/op",
            "value": 42356,
            "unit": "B/op",
            "extra": "56151 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_2 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "56151 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3",
            "value": 19609,
            "unit": "ns/op\t   42646 B/op\t      16 allocs/op",
            "extra": "61746 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - ns/op",
            "value": 19609,
            "unit": "ns/op",
            "extra": "61746 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - B/op",
            "value": 42646,
            "unit": "B/op",
            "extra": "61746 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_3 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "61746 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4",
            "value": 20569,
            "unit": "ns/op\t   41502 B/op\t      16 allocs/op",
            "extra": "57814 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - ns/op",
            "value": 20569,
            "unit": "ns/op",
            "extra": "57814 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - B/op",
            "value": 41502,
            "unit": "B/op",
            "extra": "57814 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_4 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "57814 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5",
            "value": 19986,
            "unit": "ns/op\t   42099 B/op\t      16 allocs/op",
            "extra": "60373 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - ns/op",
            "value": 19986,
            "unit": "ns/op",
            "extra": "60373 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - B/op",
            "value": 42099,
            "unit": "B/op",
            "extra": "60373 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_5 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "60373 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6",
            "value": 35876,
            "unit": "ns/op\t   41760 B/op\t      16 allocs/op",
            "extra": "32977 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - ns/op",
            "value": 35876,
            "unit": "ns/op",
            "extra": "32977 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - B/op",
            "value": 41760,
            "unit": "B/op",
            "extra": "32977 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_6 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "32977 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7",
            "value": 61502,
            "unit": "ns/op\t   36730 B/op\t      16 allocs/op",
            "extra": "19447 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - ns/op",
            "value": 61502,
            "unit": "ns/op",
            "extra": "19447 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - B/op",
            "value": 36730,
            "unit": "B/op",
            "extra": "19447 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_7 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "19447 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8",
            "value": 61464,
            "unit": "ns/op\t   37184 B/op\t      16 allocs/op",
            "extra": "19494 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - ns/op",
            "value": 61464,
            "unit": "ns/op",
            "extra": "19494 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - B/op",
            "value": 37184,
            "unit": "B/op",
            "extra": "19494 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_8 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "19494 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9",
            "value": 79082,
            "unit": "ns/op\t   36965 B/op\t      16 allocs/op",
            "extra": "15136 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - ns/op",
            "value": 79082,
            "unit": "ns/op",
            "extra": "15136 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - B/op",
            "value": 36965,
            "unit": "B/op",
            "extra": "15136 times\n4 procs"
          },
          {
            "name": "BenchmarkCompression_Gzip/level_9 - allocs/op",
            "value": 16,
            "unit": "allocs/op",
            "extra": "15136 times\n4 procs"
          }
        ]
      }
    ]
  }
}