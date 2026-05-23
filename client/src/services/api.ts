export async function csrfFetch(url: string, options?: RequestInit): Promise<Response> {
  return fetch(url, {
    credentials: 'include',
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers,
    },
  });
}
