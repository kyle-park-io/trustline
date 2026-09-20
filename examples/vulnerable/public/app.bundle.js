// Simulated production client bundle (served to every visitor).
// This intentionally contains secrets to demonstrate the scanner.
"use strict";
var exchangeRate = {
  url: "https://api.example-bank.test/rate",
  apiKey: "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
};
var authConfig = {
  adminPassword: "s3cretAdminPass90210",
  nextAuthSecret: "9f8e7d6c5b4a3f2e1d0c9b8a7654321089abcdef01234567",
};
console.log("app loaded", exchangeRate.url);
