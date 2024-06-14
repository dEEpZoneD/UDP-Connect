# UDP-Connect

## Install dependencies
  - `sudo apt-get install zlib1g zlib1g-dev libunwind-dev libevent-dev`
  - `sudo apt-get install "golang-1.20*"`

## Add Golang to path
  - `sudo cp /usr/lib/go-1.20/bin/go /usr/bin/go`
  - `go version`

## Setup submodules
  - `git submodule update --init --recursive`

## Build the project
  - `cmake . && make`
