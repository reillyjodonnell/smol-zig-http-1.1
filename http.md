# High level overview of HTTP (Hypertext Transfer Protocol)

// quick brain dump of what I know

- it's a long running server built on top of tcp
- stateless
- exposes a port which traffic goes through
- client connects to said port
- there's the 3 way handshake: syn - ack - syn-ack
- an http request has the following:
  - headers, cookies, method?, url,

Side note TDD is pretty useful in this scenario bc we already know exactly how the system should behave. The tests can guide us.
