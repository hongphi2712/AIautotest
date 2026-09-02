// Entry point: register all component modules and boot the app shell.
import './components/message-viewer.js?v=6';
import './components/intercept.js?v=6';
import './components/history.js?v=6';
import './components/dashboard.js?v=6';
import './components/sidebar.js?v=6';
import './components/repeater.js?v=6';
import './components/proxy-settings.js?v=6';
import './components/sitemap.js?v=6';
import './components/target.js?v=6';
import { AnalyzerView } from './components/analyzer.js?v=6';
import { initShell } from './shell.js?v=6';
import { connectWs } from './ws.js?v=6';

if (!customElements.get('analyzer-view')) {
  class AnalyzerViewNamed extends AnalyzerView {}
  customElements.define('analyzer-view', AnalyzerViewNamed);
}

initShell();
connectWs();
