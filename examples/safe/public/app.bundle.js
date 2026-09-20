// Simulated production client bundle - no secrets.
// Secrets stay on the server; the client only calls the app's own API routes.
"use strict";
var exchangeRate = {
  url: "/api/exchange-rate", // server route; the upstream key never reaches the browser
};
async function loadRate() {
  const res = await fetch(exchangeRate.url);
  return res.json();
}
console.log("app loaded");
