// Tiny shared store for cross-component state (tasks + proxy status).
// Components subscribe and re-render on change; no framework involved.

const state = {
  tasks: [],
  selectedTaskId: null,
  liveTaskId: null,
  proxy: { running: false, address: '' },
};

const subscribers = new Set();

function emit() {
  subscribers.forEach((fn) => fn());
}

export function subscribe(fn) {
  subscribers.add(fn);
  return () => subscribers.delete(fn);
}

export function getTasks() {
  return state.tasks;
}

export function getSelected() {
  return state.tasks.find((t) => t.id === state.selectedTaskId) || null;
}

export function getLive() {
  return state.tasks.find((t) => t.id === state.liveTaskId) || null;
}

export function getProxy() {
  return state.proxy;
}

let taskSeq = 0;

export function createTask(kind) {
  const id = 'task-' + (++taskSeq);
  const task = {
    id, kind,
    name: kind === 'live' ? 'Live passive crawl from Proxy' : 'New scan',
    status: 'idle',
    requests: 0, findings: 0, queued: 0,
  };
  state.tasks.unshift(task);
  if (kind === 'live') state.liveTaskId = task.id;
  state.selectedTaskId = task.id;
  emit();
  return task;
}

export function setTaskStatus(id, status) {
  const task = state.tasks.find((t) => t.id === id);
  if (!task) return;
  task.status = status;
  emit();
}

export function removeTask(id) {
  state.tasks = state.tasks.filter((t) => t.id !== id);
  if (state.liveTaskId === id) state.liveTaskId = null;
  if (state.selectedTaskId === id) state.selectedTaskId = null;
  emit();
}

export function selectTask(id) {
  state.selectedTaskId = id || null;
  emit();
}

export function setLiveFlowCount(flows) {
  const live = getLive();
  if (live) {
    live.requests = flows;
    emit();
  }
}

export function setProxyStatus(running, address) {
  state.proxy.running = running;
  state.proxy.address = address;
  const live = getLive();
  if (live) live.status = running ? 'running' : 'idle';
  emit();
}
