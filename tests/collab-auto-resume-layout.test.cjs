const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('launch and saved-task resume actions precede the conversation task picker', () => {
  const source = fs.readFileSync(path.join(__dirname, '../components/collab/CollabLaunchpad.js'), 'utf8');
  const actions = source.indexOf('className={styles.taskLaunchActions}');
  const picker = source.indexOf('<ConversationTaskPicker');
  assert.ok(actions > source.indexOf('className={styles.launchFields}') && actions < picker);
  const buttons = source.slice(actions, picker);
  assert.match(buttons, /type="submit"/);
  assert.match(buttons, /disabled=\{busy \|\| startingTask \|\| !selectedTask\?\.launch \|\| taskName.trim\(\) !== selectedTask.name\}/);
  assert.match(buttons, /onLaunch\(\{ \.\.\.selectedTask.launch, taskId: selectedTask.id \}\)/);
  assert.equal((source.match(/'Launch profile'/g) || []).length, 1);
});

test('task drafts survive blur and launch uses the newly created task identity', () => {
  const picker = fs.readFileSync(path.join(__dirname, '../components/collab/ConversationTaskPicker.js'), 'utf8');
  const blur = picker.slice(picker.indexOf('onBlur='), picker.indexOf('<label htmlFor='));
  assert.doesNotMatch(blur, /setQuery/);
  const launchpad = fs.readFileSync(path.join(__dirname, '../components/collab/CollabLaunchpad.js'), 'utf8');
  assert.match(launchpad, /const created = await onCreateTask\(name\);\s*if \(!created\?\.lastTaskId\) return;\s*taskId = created.lastTaskId;/);
  assert.match(launchpad, /await onLaunch\(\{\s*taskId,/);
});

test('auto-resume control stays in the right launch column with an intrinsic-width checkbox', () => {
  const page = fs.readFileSync(path.join(__dirname, '../pages/collab.js'), 'utf8');
  const css = fs.readFileSync(path.join(__dirname, '../styles/Collab.module.css'), 'utf8');
  const launchpad = fs.readFileSync(path.join(__dirname, '../components/collab/CollabLaunchpad.js'), 'utf8');
  assert.ok(!page.includes('className={styles.autoResumeControl}'));
  const control = launchpad.indexOf('className={styles.autoResumeControl}');
  const column = launchpad.indexOf('className={styles.launchFields}');
  assert.ok(column > 0 && control > column);
  assert.match(css, /\.autoResumeControl\s*\{[^}]*display: flex;[^}]*align-items: center;/);
  assert.match(css, /\.autoResumeControl input\[type='checkbox'\]\s*\{[^}]*width: auto;[^}]*flex: 0 0 auto;/);
});
