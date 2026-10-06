// Run: node tests/ui_layout_check.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const html = fs.readFileSync(path.join(__dirname, '../visualizer/dashboard.html'), 'utf8');
const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(match => match[1]);
scripts.forEach(script => new vm.Script(script));
const themeButton = {setAttribute() {}};
const preferences = new Map();
const themeDocument = {documentElement:{dataset:{}}, getElementById:()=>themeButton, addEventListener() {}};
const themeContext = vm.createContext({document:themeDocument, localStorage:{getItem:key=>preferences.get(key), setItem:(key,value)=>preferences.set(key,value)}});
vm.runInContext(scripts[0], themeContext);
assert.equal(themeDocument.documentElement.dataset.theme, 'dark');
assert.equal(themeButton.textContent, 'Light mode');
themeContext.toggleTheme();
assert.equal(preferences.get('zta-dashboard-theme'), 'light');
assert.equal(themeButton.textContent, 'Dark mode');
vm.runInContext(scripts[0], themeContext);
assert.equal(themeDocument.documentElement.dataset.theme, 'light');
themeContext.toggleTheme();
assert.equal(themeDocument.documentElement.dataset.theme, 'dark');
themeContext.applyTheme('invalid');
assert.equal(themeDocument.documentElement.dataset.theme, 'dark');
const currentSize = html.match(/function currentSize\([^)]*\)\s*\{[\s\S]*?\n\}/)[0];
for (const [, id] of currentSize.matchAll(/g\('([^']+)'\)/g))
  assert.ok(html.includes(`id="${id}"`), `Resize target missing: ${id}`);
let compact = false;
const context = vm.createContext({ compactLayout: () => compact });
vm.runInContext(html.match(/var SCENARIO_EN = \{[\s\S]*?\n\};/)[0], context);
assert.equal(Object.keys(context.SCENARIO_EN).length, 34);
for (let number = 1; number <= 34; number++) {
  const copy = context.SCENARIO_EN['S' + String(number).padStart(2, '0')];
  assert.equal(copy.length, 2);
  assert.ok(copy.every(text => typeof text === 'string' && text.length > 0 && !/[가-힣]/.test(text)));
}
assert.doesNotMatch(html.match(/<iframe[^>]*id="kiali-frame"[^>]*>/)[0], /\ssrc=/);
for (const name of ['clampSize', 'resizeAxis']) {
  const match = html.match(new RegExp('function ' + name + '\\([^)]*\\)\\s*\\{[\\s\\S]*?\\n\\}'));
  assert.ok(match, `Missing ${name}`);
  vm.runInContext(match[0], context);
}
for (const [minimum, maximum] of [[240, 600], [140, 420]]) {
  assert.equal(context.clampSize(-100, minimum, maximum), minimum);
  assert.equal(context.clampSize(300, minimum, maximum), 300);
  assert.equal(context.clampSize(9999, minimum, maximum), maximum);
  assert.equal(context.clampSize(NaN, minimum, maximum), minimum);
  assert.equal(context.clampSize(Infinity, minimum, maximum), minimum);
}
assert.equal(context.clampSize(300, 400, 100), 400);
for (const name of ['list', 'logs', 'expected']) assert.equal(context.resizeAxis(name), 'x');
for (const name of ['main', 'workspace']) assert.equal(context.resizeAxis(name), 'y');
compact = true;
context.g = id => id === 'bottom-panels' ? {clientHeight:300} : {clientHeight:520};
context.window = {innerWidth:800, innerHeight:900};
vm.runInContext(html.match(/function sizeLimits\([^)]*\)\s*\{[\s\S]*?\n\}/)[0], context);
assert.equal(context.sizeLimits('logs')[1], 203); // Reserve 90px for performance plus the 7px separator.
for (const name of ['list', 'logs', 'expected', 'main', 'workspace']) assert.equal(context.resizeAxis(name), 'y');
console.log('PASS: scripts, English34, lazy iframe, dark default, theme persistence, resize targets/limits/axes');
