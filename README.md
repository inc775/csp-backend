# 4ARMED's CSP Generator

This is the backend API for 4ARMED's Content Security Policy Generator. It provides a CSP report-uri handler along with the ability to generate a CSP based on reported violations.

It's sole interface is a JSON API. The easiest way to run it using Docker using our [docker-compose.yml](https://github.com/4armed/csp-generator) and the easiest way to interact with it is via our [Google Chrome Extension](https://github.com/4armed/csp-generator-extension).