# CornedBeefSandwich-server
Server for the Gemini protocol

## Config

The server reads a yaml file named "cbs.conf" from the current directory at startup.  It cares about these variables:

- addr - IP address to bind to (defaults to 0.0.0.0 if not present)
- port - TCP port to listen on (defaults to 1965 if not present)
- cert - Certificate file (PEM format)
- pkey - Private key file (PEM format)
- servedir - Directory containing content to serve
- cgidir - Directory containing CGI scripts, relative to "servedir" (CGI disabled when not present)
