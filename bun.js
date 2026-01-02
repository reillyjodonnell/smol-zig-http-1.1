const server = Bun.serve({
  port: 3003,
  fetch(req) {
    return new Response('Hello', {
      headers: {
        'Content-Type': 'text/plain',
      },
    });
  },
});

console.log(`Server running at http://localhost:${server.port}`);
