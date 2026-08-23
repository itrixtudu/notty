import { useState } from 'react';

const defaultForm = {
  shell: '',
  cols: 80,
  rows: 24,
  cwd: ''
};

export default function TerminalCreator({ onCreate, busy }) {
  const [form, setForm] = useState(defaultForm);

  const update = (field, value) => {
    setForm((prev) => ({ ...prev, [field]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (busy) return;
    await onCreate({
      shell: form.shell || undefined,
      cols: form.cols ? Number(form.cols) : undefined,
      rows: form.rows ? Number(form.rows) : undefined,
      cwd: form.cwd || undefined
    });
    setForm(defaultForm);
  };

  return (
    <form className="card" onSubmit={handleSubmit}>
      <div className="card-header">
        <h3>Create Terminal</h3>
        <p>Spawn a PTY with optional shell, dimensions, and cwd overrides.</p>
      </div>

      <label>
        Shell
        <input
          type="text"
          placeholder="bash"
          value={form.shell}
          onChange={(e) => update('shell', e.target.value)}
        />
      </label>

      <div className="row">
        <label>
          Columns
          <input
            type="number"
            min="20"
            value={form.cols}
            onChange={(e) => update('cols', e.target.value)}
          />
        </label>
        <label>
          Rows
          <input
            type="number"
            min="10"
            value={form.rows}
            onChange={(e) => update('rows', e.target.value)}
          />
        </label>
      </div>

      <label>
        Working Directory
        <input
          type="text"
          placeholder="/workspace"
          value={form.cwd}
          onChange={(e) => update('cwd', e.target.value)}
        />
      </label>

      <button type="submit" disabled={busy}>
        {busy ? 'Spawning…' : 'Create Terminal'}
      </button>
    </form>
  );
}
