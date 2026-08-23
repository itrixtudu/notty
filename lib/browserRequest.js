export function resolveBrowserUrl(target) {
  if (typeof window === 'undefined') {
    return target;
  }

  const baseUrl = new URL(window.location.href);
  baseUrl.username = '';
  baseUrl.password = '';

  const url = new URL(target, baseUrl);
  url.username = '';
  url.password = '';
  return url.toString();
}

export function browserFetch(target, options) {
  return fetch(resolveBrowserUrl(target), options);
}
