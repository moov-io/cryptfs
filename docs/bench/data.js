window.BENCHMARK_DATA = {
  "lastUpdate": 1790147285140,
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
      }
    ]
  }
}