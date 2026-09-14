window.BENCHMARK_DATA = {
  "lastUpdate": 1789400823444,
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
      }
    ]
  }
}