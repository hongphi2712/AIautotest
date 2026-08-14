// Entry point: register all component modules and boot the app shell.
import './components/message-viewer.js';
import './components/intercept.js';
import './components/history.js';
import './components/dashboard.js';
import './components/sidebar.js';
import './components/repeater.js';
import './components/proxy-settings.js';
import { initShell } from './shell.js';

initShell();
