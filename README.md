# UDP-Connect

## Install dependencies
  - `sudo apt-get install zlib1g zlib1g-dev libunwind-dev libevent-dev`

## Install and add Golang (version>=1.19) to path
  - `sudo apt-get install "golang-1.20*"`
  - `sudo cp /usr/lib/go-1.20/bin/go /usr/bin/go`
  - `go version`

## Setup submodules
  - `git submodule update --init --recursive`

## Build the project
  - `cmake . && make`

## Run example
  - `./client -vl debug`
  - `./udp_proxy`