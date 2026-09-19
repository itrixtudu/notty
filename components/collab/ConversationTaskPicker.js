import { useEffect, useId, useRef, useState } from 'react';
import styles from '../../styles/Collab.module.css';

export default function ConversationTaskPicker({ tasks, busy, onSelect, onCreate, query, setQuery }) {
  const entries = tasks?.tasks || [];
  const selected = entries.find((entry) => entry.id === tasks?.lastTaskId);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [pending, setPending] = useState(false);
  const pendingRef = useRef(false);
  const inputRef = useRef(null);
  const id = useId();
  useEffect(() => { setQuery(selected?.name || ''); }, [selected?.id, selected?.name]);
  const name = query.trim();
  const matches = entries.filter((entry) => !name || query === selected?.name
    || entry.name.toLowerCase().includes(name.toLowerCase()));
  const options = matches.map((entry) => ({ id: entry.id, label: entry.name }));
  if (name && !entries.some((entry) => entry.name.toLowerCase() === name.toLowerCase())) {
    options.push({ id: null, label: `Create “${name}”`, name });
  }
  const activeIndex = Math.min(active, options.length - 1);
  const disabled = busy || pending;
  const choose = async (option) => {
    if (!option || disabled || pendingRef.current) return;
    pendingRef.current = true;
    setPending(true);
    try {
      const success = option.id ? await onSelect({ taskId: option.id }) : await onCreate(option.name);
      if (success !== false) {
        setQuery(option.name || option.label);
        setOpen(false);
      }
    } finally {
      pendingRef.current = false;
      setPending(false);
    }
  };
  return <div className={styles.taskPicker} onBlur={(event) => {
    if (!event.currentTarget.contains(event.relatedTarget)) {
      setOpen(false);
    }
  }}>
    <label htmlFor={id}>Conversation task</label>
    <div className={styles.taskPickerInput}>
      <input ref={inputRef} id={id} role="combobox" aria-autocomplete="list" aria-expanded={open}
        aria-controls={open ? `${id}-options` : undefined}
        aria-activedescendant={open && activeIndex >= 0 ? `${id}-${activeIndex}` : undefined}
        autoComplete="off" maxLength={120} value={query} disabled={disabled}
        placeholder="Select or type a new task…"
        onFocus={() => { setOpen(true); setActive(0); }}
        onChange={(event) => { setQuery(event.target.value); setOpen(true); setActive(0); }}
        onKeyDown={(event) => {
          if (event.nativeEvent.isComposing) return;
          if (event.key === 'Escape') {
            event.preventDefault(); event.stopPropagation(); setOpen(false); setQuery(selected?.name || '');
          } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault(); setOpen(true);
            setActive((current) => Math.max(0, Math.min(options.length - 1,
              current + (event.key === 'ArrowDown' ? 1 : -1))));
          } else if (event.key === 'Enter' && open) {
            event.preventDefault(); choose(options[activeIndex]);
          }
        }} />
      <button type="button" aria-label="Show conversation tasks" disabled={disabled}
        onClick={() => { inputRef.current?.focus(); setOpen(!open); setActive(0); }}>▾</button>
    </div>
    {open && <ul id={`${id}-options`} role="listbox" aria-label="Conversation tasks" className={styles.taskPickerOptions}>
      {options.map((option, index) => <li key={option.id || 'create'} id={`${id}-${index}`}
        role="option" aria-selected={index === activeIndex}
        onMouseDown={(event) => event.preventDefault()}
        onMouseEnter={() => setActive(index)} onClick={() => choose(option)}>{option.label}</li>)}
      {!options.length && <li role="presentation">Type a name to create a task.</li>}
    </ul>}
  </div>;
}
