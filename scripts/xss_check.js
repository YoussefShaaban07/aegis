// Judge round 17: attacker-controlled strings (Logix tag names, copilot input) must never run as code on the
// dashboards. Start the demo server on port 8777 (PORT=8777 python -m aegis.server), send an EtherNet/IP Logix
// write whose tag name is an HTML payload, then: node scripts/xss_check.js   (expects "xss executed: 0")
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch(); const p = await b.newPage();
  let dialogs=0; p.on('dialog', d=>{dialogs++; d.dismiss();});
  await p.goto('http://127.0.0.1:8777'); await p.waitForTimeout(600);
  await p.fill('#lu','engineer'); await p.fill('#lp','engineer'); await p.keyboard.press('Enter'); await p.waitForTimeout(1200);
  const P='<img src=x onerror="window.__xss=1">';
  const H={'Content-Type':'application/json','X-Aegis':'1'};
  const r=await p.evaluate(async([P,H])=>{
    const out={};
    for (const [u,b] of [['/api/copilot',{message:P}],['/api/lab',{name:'raw_alkalinity',value:1,by:P}],['/api/alerts/test',{message:P}]]) {
      const x=await fetch(u,{method:'POST',headers:H,body:JSON.stringify(b)}); out[u]=x.status; }
    return out;},[P,H]);
  console.log('posts', JSON.stringify(r));
  await p.waitForTimeout(4000);
  for (const t of ['','#']) { await p.evaluate(()=>{for(const b of document.querySelectorAll('.tabs button'))b.click();}); await p.waitForTimeout(800); }
  const x=await p.evaluate(()=>window.__xss||0);
  const shown=await p.evaluate(()=>document.body.innerText.includes('onerror'));
  console.log('xss executed:',x,'| payload visible as text:',shown,'| dialogs',dialogs);
  await p.goto('http://127.0.0.1:8777/operator'); await p.waitForTimeout(2000);
  console.log('operator page xss:', await p.evaluate(()=>window.__xss||0));
  await b.close();
})();
