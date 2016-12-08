# 4ARMED's CSP Generator

This is the backend API for 4ARMED's Content Security Policy Generator. It provides a CSP report-uri handler along with the ability to generate a CSP based on reported violations.

It's sole interface is a JSON API. The easiest way to run it using Docker using our [docker-compose.yml](https://github.com/4armed/csp-generator) and the easiest way to interact with it is via our [Google Chrome Extension](https://github.com/4armed/csp-generator-extension).

## Prerequisites

If you are not installing it in Docker then you're probably either crazy or you're looking to hack this thing into shape. You're going to need a couple of things.

1. Ruby

   This thing is written in Ruby. I used 2.3 but it should be good for any 2.0+ release of MRI.

   I recommended using RVM or rbenv to get your Ruby installed.

2. MongoDB

   The backend data store is MongoDB so you will need an instance of this running. If you're on macOS you can use HomeBrew (if you've installed it) and do:

   ```shell
   $ brew install mongo
   ```

   Once installed, make sure it's running:

   ```shell
   $ mongod --config /usr/local/etc/mongod.conf &
   ```

