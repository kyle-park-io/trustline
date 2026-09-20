// Updates a DNS record. Uses Cloudflare's GLOBAL API key, which can edit every
// zone and setting on the account. A scoped API token (Bearer) should be used.
async function updateRecord(zoneId, recordId, body) {
  return fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${recordId}`, {
    method: "PUT",
    headers: {
      "X-Auth-Email": process.env.CF_EMAIL,
      "X-Auth-Key": process.env.CF_API_KEY,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
}

module.exports = { updateRecord };
