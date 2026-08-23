(function redirectCredentialUrl() {
  'use strict';

  try {
    var current = new URL(document.URL);
    if (!current.username && !current.password) {
      return;
    }

    current.username = '';
    current.password = '';
    window.location.replace(current.toString());
  } catch (_error) {
    // A normal credential-free document can continue without intervention.
  }
})();
