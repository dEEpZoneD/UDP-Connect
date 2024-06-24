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
  - `mkdir build`
  - `cd build`
  - `cmake .. && make`

## Run example
  - `./client -t 127.0.0.1 -p 192.168.255.255 -l debug`  /*only an example*/
  - `./udp_proxy`-c mycert-cert.pem -k mycert-key.pem -l debug
