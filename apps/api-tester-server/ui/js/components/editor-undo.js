// Shared undo/redo for the syntax-highlighted HTTP editors (Intercept and
// Repeater). The editors re-render their highlighted DOM on every keystroke,
// which destroys the browser's native contenteditable undo stack, so undo and
// redo are managed here with an explicit snapshot stack (the industry-standard
// approach for highlighted editors — the browser's native contenteditable undo
// is unreliable once the DOM is rewritten programmatically).
//
// History actions are intercepted on `beforeinput` (`historyUndo` /
// `historyRedo`) so undo/redo from the context menu, the menu bar, or rebound
// keys work too — not just Ctrl/Cmd+Z / Y. IME composition is excluded from
// snapshots so a composition (e.g. Vietnamese input) becomes a single undo step.

const MAX_UNDO = 200;

/// Returns the caret offset (in plain-text characters) inside a contenteditable.
export function caretOffset(element) {
  const selection = window.getSelection();
  if (!selection.rangeCount) return 0;
  const range = selection.getRangeAt(0);
  const clone = range.cloneRange();
  clone.selectNodeContents(element);
  clone.setEnd(range.endContainer, range.endOffset);
  return clone.toString().length;
}

/// Places the caret at a plain-text character offset inside a contenteditable.
export function setCaret(element, offset) {
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
  let remaining = offset;
  let node = walker.nextNode();
  let target = element;
  let pos = 0;
  while (node) {
    const length = node.textContent.length;
    if (remaining <= length) {
      target = node;
      pos = remaining;
      break;
    }
    remaining -= length;
    node = walker.nextNode();
  }
  const range = document.createRange();
  range.setStart(target, pos);
  range.collapse(true);
  const selection = window.getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
}

/// Creates an undo/redo manager bound to a contenteditable `element`.
/// `render(text, caret)` must re-render the editor DOM from `text` and restore
/// the caret (highlight + line numbers + any per-editor side effects).
/// Returns `{ commit, reset }`:
/// - `commit(text)`: record a user edit (call after the DOM already changed).
/// - `reset(text)`: clear history for a freshly loaded document.
export function createUndoRedo({ element, render }) {
  const undoStack = [];
  const redoStack = [];
  let lastText = null;
  let lastCaret = 0;

  function pushUndo(text, caret) {
    if (undoStack.length && undoStack[undoStack.length - 1].text === text) return;
    if (undoStack.length >= MAX_UNDO) undoStack.shift();
    undoStack.push({ text, caret });
  }

  function apply(state) {
    lastText = state.text;
    lastCaret = state.caret;
    render(state.text, state.caret);
  }

  function undo() {
    if (element.isComposing) return;
    const state = undoStack.pop();
    if (!state) return;
    redoStack.push({ text: lastText, caret: lastCaret });
    apply(state);
  }

  function redo() {
    if (element.isComposing) return;
    const state = redoStack.pop();
    if (!state) return;
    undoStack.push({ text: lastText, caret: lastCaret });
    apply(state);
  }

  element.addEventListener('keydown', (event) => {
    if (!(event.ctrlKey || event.metaKey)) return;
    const key = event.key.toLowerCase();
    if (key === 'z') {
      event.preventDefault();
      if (event.shiftKey) redo();
      else undo();
    } else if (key === 'y') {
      event.preventDefault();
      redo();
    }
  });

  element.addEventListener('beforeinput', (event) => {
    if (event.inputType === 'historyUndo') {
      event.preventDefault();
      undo();
    } else if (event.inputType === 'historyRedo') {
      event.preventDefault();
      redo();
    }
  });

  function commit(text) {
    const caret = caretOffset(element);
    if (element.isComposing) {
      // Keep the baseline current so the whole composition becomes one undo step.
      lastText = text;
      lastCaret = caret;
      return;
    }
    if (lastText !== null && text !== lastText) {
      pushUndo(lastText, lastCaret);
      redoStack.length = 0;
    }
    lastText = text;
    lastCaret = caret;
  }

  function reset(text) {
    undoStack.length = 0;
    redoStack.length = 0;
    lastText = text;
    lastCaret = 0;
  }

  return { commit, reset };
}
