export function isJsonRequest(req) {
  const header = req?.headers?.['content-type'];
  if (typeof header !== 'string') {
    return false;
  }
  const mediaType = header.split(';', 1)[0].trim().toLowerCase();
  return mediaType === 'application/json'
    || (mediaType.startsWith('application/') && mediaType.endsWith('+json'));
}
