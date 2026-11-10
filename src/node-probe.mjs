// Node only. Asks for the plain-http address the way a browser's address bar does, and reports where it leads.
// Node's fetch adds headers of its own that some sites answer differently, so the CLI uses this instead.
import http from "node:http";

export const httpProbe = (url, timeout = 6000) =>
  new Promise((resolve) => {
    const req = http.get(url, { timeout, headers: { "user-agent": "greenlit (+https://greenlit.priberry.com)", accept: "text/html,*/*" } }, (res) => {
      res.resume();
      resolve({ status: res.statusCode, location: res.headers.location || "" });
    });
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve({ status: 0, location: "" }));
  });
