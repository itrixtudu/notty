function boundedLabel(value, fallback) {
  const normalized = typeof value === 'string' ? value.trim() : '';
  return (normalized || fallback).slice(0, 120);
}

export function safeRequestErrorDetails(error) {
  const statusCode = Number.isInteger(error?.statusCode)
    ? error.statusCode
    : Number.isInteger(error?.status)
      ? error.status
      : null;
  return {
    name: boundedLabel(error?.name, 'Error'),
    code: boundedLabel(error?.code || error?.type, 'request_error'),
    ...(statusCode === null ? {} : { statusCode })
  };
}

export function jsonBodyErrorHandler(error, _req, res, next) {
  const isBodyParserError = typeof error?.type === 'string'
    && error.type.startsWith('entity.');
  const carriesRawBody = Object.prototype.hasOwnProperty.call(error || {}, 'body');
  if (!isBodyParserError && !carriesRawBody) {
    next(error);
    return;
  }

  // Body-parser errors can retain the complete request in error.body. Never
  // log the error object or its message because a malformed body may contain
  // an OTP or another credential.
  console.error('[http] rejected JSON request body:', safeRequestErrorDetails(error));
  res.status(Number.isInteger(error?.status) ? error.status : 400).json({
    error: {
      code: 'invalid_json_body',
      message: 'Request body must be valid JSON.'
    }
  });
}
