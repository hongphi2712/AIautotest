// Collapsible inspector sidebar. Usage: `<inspector-panel></inspector-panel>`,
// then `panel.data = { sections: [{ title, rows: [[name, value], ...] }] }`.
// Reused by the Repeater (and available for history/intercept).
const TEMPLATE = `
  <div class="inspector-title">Inspector</div>
  <div class="inspector-sections" id="sections"></div>
`;

export class InspectorPanel extends HTMLElement {
  connectedCallback() {
    this.innerHTML = TEMPLATE;
    this._sections = [];
  }

  set data(value) {
    this._sections = (value && value.sections) || [];
    this.render();
  }

  render() {
    const container = this.querySelector('#sections');
    container.innerHTML = '';
    this._sections.forEach((section, index) => {
      const details = document.createElement('details');
      details.className = 'inspector-group';
      if (index === 0) details.open = true;
      const summary = document.createElement('summary');
      summary.textContent = section.title;
      const count = document.createElement('span');
      count.className = 'inspector-count';
      count.textContent = ` [${section.rows.length}]`;
      summary.appendChild(count);
      const content = document.createElement('div');
      content.className = 'inspector-content';
      if (section.rows && section.rows.length) {
        content.textContent = section.rows
          .map(([name, value]) => `${name} = ${value}`)
          .join('\n');
      } else {
        content.textContent = 'No items';
      }
      details.appendChild(summary);
      details.appendChild(content);
      container.appendChild(details);
    });
  }
}

customElements.define('inspector-panel', InspectorPanel);
