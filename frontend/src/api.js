const encode = (values) => new URLSearchParams(values);

export async function request(path, options) {
  const response = await fetch(path, options);
  const text = await response.text();
  let payload;
  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    payload = { message: text };
  }
  if (!response.ok) throw new Error(payload.message || payload.error || `Request failed (${response.status})`);
  return payload;
}

export async function getJson(path) {
  return request(path);
}

export async function submit(path, values) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: encode(values),
  });
  if (!response.ok) throw new Error((await response.text()) || `Request failed (${response.status})`);
}
