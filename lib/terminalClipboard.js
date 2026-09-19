export async function copyTerminalText(field, all, clipboard, documentObject) {
  const start = all ? 0 : field.selectionStart;
  const end = all ? field.value.length : field.selectionEnd;
  const text = field.value.slice(start, end);
  if (!text) return 'Select some text first.';
  try {
    if (!clipboard?.writeText) throw new Error('Clipboard unavailable');
    await clipboard.writeText(text);
    return 'Copied';
  } catch {
    if (field.isConnected === false) return 'Copy view closed.';
    // Restore the exact requested selection if permission was delayed/denied.
    field.focus();
    field.setSelectionRange(start, end);
    try {
      if (documentObject.execCommand('copy')) return 'Copied';
    } catch { /* Keep selectable text available for manual browser copying. */ }
    return 'Copy unavailable. Use your browser’s Copy command.';
  }
}
