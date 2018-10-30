You won't be able to simply open `index.html` in your browser. For security purposes, your browser will refuse to load the WASM:

```
Fetch API cannot load file:///Users/robbie/Programs/4thA/S4_Javascript/dist.browser/libS4.wasm. URL scheme must be "http" or "https" for CORS request.
```

So the solution is to use a local webserver. Something like `serve` works fine:

```
$ npm install -g serve
$ cd <to s4js ROOT directory>
$ serve
   ┌───────────────────────────────────────────────────┐
   │                                                   │
   │   Serving!                                        │
   │                                                   │
   │   - Local:            http://localhost:5000       │
   │   - On Your Network:  http://192.168.1.212:5000   │
   │                                                   │
   │   Copied local address to clipboard!              │
   │                                                   │
   └───────────────────────────────────────────────────┘
```

Note that you need to run serve from the project ROOT directory. This is because we need to reference files in `/dist.browser`.

Finally, run the example in your browser:

```
http://localhost:5000/examples/web/index.html
```