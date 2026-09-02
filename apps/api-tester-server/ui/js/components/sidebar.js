import { apiPost, escapeHtml, showError } from '../api.js';
import {
  getTasks, getSelected, getLive, createTask, setTaskStatus, removeTask, selectTask, subscribe,
} from '../store.js';

const TEMPLATE = `
  <div class="sidebar-head">Tasks</div>
  <button class="new-task" id="new-scan">+ New scan</button>
  <button class="new-task" id="new-live">+ New live task</button>
  <div id="task-list"></div>
`;

export class TaskSidebar extends HTMLElement {
  connectedCallback() {
    this.innerHTML = TEMPLATE;
    this.querySelector('#new-scan').addEventListener('click', () => createTask('scan'));
    this.querySelector('#new-live').addEventListener('click', async () => {
      createTask('live');
      try {
        await apiPost('/api/proxy/start');
      } catch (error) {
        showError('Proxy error: ' + error);
      }
      window.dispatchEvent(new CustomEvent('app:refresh-proxy'));
    });
    this.unsubscribe = subscribe(() => this.render());
    this.render();
  }

  disconnectedCallback() {
    if (this.unsubscribe) this.unsubscribe();
  }

  render() {
    const list = this.querySelector('#task-list');
    const tasks = getTasks();
    const selected = getSelected();
    list.innerHTML = '';
    tasks.forEach((task) => {
      const item = document.createElement('div');
      item.className = 'task-item' + (selected && selected.id === task.id ? ' selected' : '');
      item.innerHTML = `
        <div class="t-name"><span class="t-status ${task.status}"></span><span>${escapeHtml(task.name)}</span></div>
        <div class="t-meta">${task.status} Â· ${task.requests} req Â· ${task.findings} findings</div>
        <div class="t-actions"></div>`;
      item.onclick = () => selectTask(task.id);
      const actions = item.querySelector('.t-actions');
      if (task.status === 'running') actions.appendChild(this.actionButton('Pause', () => setTaskStatus(task.id, 'paused')));
      if (task.status === 'paused') actions.appendChild(this.actionButton('Resume', () => setTaskStatus(task.id, 'running')));
      if (task.status === 'running' || task.status === 'paused') {
        actions.appendChild(this.actionButton('Stop', () => {
          setTaskStatus(task.id, 'stopped');
          if (task.id === getLive()?.id) {
            apiPost('/api/proxy/stop').then(() => window.dispatchEvent(new CustomEvent('app:refresh-proxy')));
          }
        }));
      }
      actions.appendChild(this.actionButton('Remove', () => removeTask(task.id)));
      list.appendChild(item);
    });
  }

  actionButton(label, onClick) {
    const button = document.createElement('button');
    button.textContent = label;
    button.addEventListener('click', (event) => {
      event.stopPropagation();
      onClick();
    });
    return button;
  }
}

if (!customElements.get('task-sidebar')) customElements.define('task-sidebar', TaskSidebar);
