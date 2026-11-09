/**
 * CyberThreat AI System - API Client Service
 * 
 * Provides unified HTTP client methods connecting the React frontend
 * to the FastAPI Python research backend.
 */

export const PUBLIC_CLOUD_BACKEND = 'https://cyberzen.13.211.114.156.sslip.io/api';

const getInitialApiBase = () => {
  if (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_URL) {
    return import.meta.env.VITE_API_URL;
  }
  if (typeof window !== 'undefined') {
    const stored = localStorage.getItem('cyberthreat_api_base');
    if (stored && (stored.includes('127.0.0.1') || stored.includes('localhost'))) {
      localStorage.removeItem('cyberthreat_api_base');
    } else if (stored && stored.startsWith('http')) {
      return stored;
    }
  }
  return PUBLIC_CLOUD_BACKEND;
};

let activeApiBase = getInitialApiBase();

async function fetchWithFallback(endpointPath, options = {}) {
  const timeoutMs = options.timeout || 8000;
  let url = activeApiBase + endpointPath;
  try {
    const res = await fetch(url, {
      ...options,
      signal: AbortSignal.timeout(timeoutMs)
    });
    return res;
  } catch (err) {
    if (activeApiBase !== PUBLIC_CLOUD_BACKEND) {
      console.warn('[apiClient] Primary request failed. Seamlessly retrying with Public Cloud Backend...', err.message);
      activeApiBase = PUBLIC_CLOUD_BACKEND;
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem('cyberthreat_api_base', PUBLIC_CLOUD_BACKEND);
      }
      return await fetch(PUBLIC_CLOUD_BACKEND + endpointPath, {
        ...options,
        signal: AbortSignal.timeout(timeoutMs)
      });
    }
    throw err;
  }
}

const API_BASE = {
  toString() { return activeApiBase; },
  valueOf() { return activeApiBase; }
};

export const apiClient = {getApiBase(){return activeApiBase},getToken(){return localStorage.getItem(`cyberthreat_auth_token`)||``},setToken(e){e?localStorage.setItem(`cyberthreat_auth_token`,e):localStorage.removeItem(`cyberthreat_auth_token`)},clearToken(){localStorage.removeItem(`cyberthreat_auth_token`)},getAuthHeaders(){let e=this.getToken(),t={"Content-Type":`application/json`};return e&&(t.Authorization=`Bearer ${e}`),t},async signup(email, password, name, device_id = null, os_info = '', consent_accepted = true) {
    try {
      const res = await fetchWithFallback('/auth/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          password,
          name,
          device_id,
          os_info,
          consent_accepted
        }),
        timeout: 8000
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Signup failed');
      if (data.token) this.setToken(data.token);
      return data;
    } catch (err) {
      throw err;
    }
  },
  async verifyEmail(email, code) {
    try {
      const res = await fetchWithFallback('/auth/verify-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code }),
        timeout: 8000
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Email verification failed');
      return data;
    } catch (err) {
      throw err;
    }
  },
  async resendVerification(email) {
    try {
      const res = await fetchWithFallback('/auth/resend-verification', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
        timeout: 8000
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Resend verification failed');
      return data;
    } catch (err) {
      throw err;
    }
  },
  async login(email, password, device_id = null, os_info = '') {
    try {
      const res = await fetchWithFallback('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, device_id, os_info }),
        timeout: 8000
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Login failed');
      if (data.token) this.setToken(data.token);
      return data;
    } catch (err) {
      throw err;
    }
  },
  async getCurrentUser(e=null){try{let t=`${API_BASE}/auth/me`;e&&(t+=`?user_id=${encodeURIComponent(e)}`);let n=await fetch(t,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(4e3)});return n.ok?await n.json():{authenticated:!1}}catch{return{authenticated:!1}}},async openDesktopApp(){try{let e=await fetch(`${API_BASE}/system/open-desktop-app`,{method:`POST`,headers:this.getAuthHeaders(),signal:AbortSignal.timeout(5e3)}),t=await e.json();if(!e.ok)throw Error(t.detail||`Could not launch desktop app`);return t}catch(e){throw e}},async launchProtectedBrowser(e=`https://google.com`){try{let t=await fetch(`${API_BASE}/browser/launch`,{method:`POST`,headers:{"Content-Type":`application/json`,...this.getAuthHeaders()},body:JSON.stringify({url:e}),signal:AbortSignal.timeout(6e3)}),n=await t.json();if(!t.ok)throw Error(n.detail||`Could not launch protected browser`);return n}catch(e){throw console.warn(`[apiClient] launchProtectedBrowser failed:`,e),e}},async getIncident(e){try{let t=await fetch(`${API_BASE}/incidents/${encodeURIComponent(e)}`,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(4e3)});return t.ok?await t.json():null}catch(e){return console.warn(`[apiClient] getIncident failed:`,e),null}},async resolveIncident(e){try{let t=await fetch(`${API_BASE}/incidents/${encodeURIComponent(e)}/resolve`,{method:`POST`,headers:{"Content-Type":`application/json`,...this.getAuthHeaders()},signal:AbortSignal.timeout(5e3)}),n=await t.json();if(!t.ok)throw Error(n.detail||`Could not resolve incident`);return n}catch(e){throw console.warn(`[apiClient] resolveIncident failed:`,e),e}},async deleteIncident(e){try{let t=await fetch(`${API_BASE}/incidents/${encodeURIComponent(e)}`,{method:`DELETE`,headers:this.getAuthHeaders(),signal:AbortSignal.timeout(5e3)}),n=await t.json();if(!t.ok)throw Error(n.detail||`Could not delete incident`);return n}catch(e){throw console.warn(`[apiClient] deleteIncident failed:`,e),e}},async getHealth() {
    try {
      const res = await fetch(`${activeApiBase}/health`, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return await res.json();
      throw new Error(`HTTP ${res.status}`);
    } catch (err) {
      if (activeApiBase !== PUBLIC_CLOUD_BACKEND) {
        try {
          const res = await fetch(`${PUBLIC_CLOUD_BACKEND}/health`, { signal: AbortSignal.timeout(3000) });
          if (res.ok) {
            console.log('[*] Falling back to Public Cloud Backend:', PUBLIC_CLOUD_BACKEND);
            activeApiBase = PUBLIC_CLOUD_BACKEND;
            if (typeof localStorage !== 'undefined') {
              localStorage.setItem('cyberthreat_api_base', PUBLIC_CLOUD_BACKEND);
            }
            return await res.json();
          }
        } catch (_) {}
      }
      return null;
    }
  },
  async getDeviceStatus(e=null){try{let t=`${API_BASE}/device/status`;e&&(t+=`?device_id=${encodeURIComponent(e)}`);let n=await fetch(t,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(3e3)});if(!n.ok)throw Error(`HTTP ${n.status}`);return await n.json()}catch{return null}},async getDevices(e){try{let t=e?`?user_id=${encodeURIComponent(e)}`:``,n=await fetch(`${API_BASE}/devices${t}`,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(4e3)});if(!n.ok)throw Error(`HTTP ${n.status}`);return await n.json()}catch{return{devices:[]}}},async enrollDevice(e,t=`Windows 11 (64-bit)`,n=null,r=null){try{let i=e,a=t,o=n,s=r;typeof e==`object`&&e&&(i=e.device_name||e.deviceName||`My Laptop`,a=e.os_info||e.osInfo||`Windows 11 (64-bit)`,o=e.device_id||e.deviceId||null,s=e.user_id||e.userId||null);let c=await fetch(`${API_BASE}/devices/enroll`,{method:`POST`,headers:this.getAuthHeaders(),body:JSON.stringify({device_name:i,os_info:a,device_id:o,user_id:s}),signal:AbortSignal.timeout(5e3)}),l=await c.json();if(!c.ok)throw Error(l.detail||`Device enrollment failed`);return l}catch(e){throw e}},async renameDevice(e,t){try{let n=await fetch(`${API_BASE}/devices/${encodeURIComponent(e)}`,{method:`PUT`,headers:this.getAuthHeaders(),body:JSON.stringify({device_name:t}),signal:AbortSignal.timeout(4e3)}),r=await n.json();if(!n.ok)throw Error(r.detail||`Rename failed`);return r}catch(e){throw e}},async revokeDevice(e){try{let t=await fetch(`${API_BASE}/devices/${encodeURIComponent(e)}`,{method:`POST`,headers:this.getAuthHeaders(),body:JSON.stringify({}),signal:AbortSignal.timeout(4e3)}),n=await t.json();if(!t.ok)throw Error(n.detail||`Revoke failed`);return n}catch(e){throw e}},async removeDevice(e){try{let t=await fetch(`${API_BASE}/devices/${encodeURIComponent(e)}`,{method:`DELETE`,headers:this.getAuthHeaders(),signal:AbortSignal.timeout(4e3)}),n=await t.json();if(!t.ok)throw Error(n.detail||`Remove failed`);return n}catch(e){throw e}},async getDownloadInfo(){try{let e=await fetch(`${API_BASE}/download/info`,{signal:AbortSignal.timeout(4e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch{return{version:`1.0.0`,filename:`CyberThreat-AI-Setup-1.0.0.exe`,platform:`Windows`,supported_os:`Windows 10, Windows 11 (64-bit)`,file_size_bytes:0,file_size_mb:0,sha256_checksum:`Pending Build`,download_url:`${API_BASE}/download/windows`,publisher_signing_status:`Self-Signed / Developer Release`,is_signed:!1,release_notes:[]}}},async registerDevice(e,t,n,r=``){try{return await(await fetch(`${API_BASE}/devices/register`,{method:`POST`,headers:{"Content-Type":`application/json`},body:JSON.stringify({device_id:e,user_id:t,device_name:n,os_info:r}),signal:AbortSignal.timeout(4e3)})).json()}catch{return null}},async getEvents(e=100,t=null,n=null){try{let r={};r=typeof e==`object`&&e?e:{limit:e,userId:t,minRisk:n};let i=new URLSearchParams;r.limit!==void 0&&i.set(`limit`,r.limit),r.deviceId&&i.set(`device_id`,r.deviceId),r.userId&&i.set(`user_id`,r.userId),r.minRisk!==void 0&&r.minRisk!==null&&i.set(`min_risk`,r.minRisk),r.date&&i.set(`date`,r.date),r.startDate&&i.set(`start_date`,r.startDate),r.endDate&&i.set(`end_date`,r.endDate),r.clientTzOffset!==void 0&&r.clientTzOffset!==null&&i.set(`client_tz_offset`,r.clientTzOffset),r.offset!==void 0&&i.set(`offset`,r.offset),r.excludeTest!==void 0&&i.set(`exclude_test`,r.excludeTest),r.activityDomain&&i.set(`activity_domain`,r.activityDomain),r.syncStatus&&i.set(`sync_status`,r.syncStatus);let a=await fetch(`${API_BASE}/telemetry/events?${i.toString()}`,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(8e3)});if(!a.ok)throw Error(`HTTP ${a.status}`);return await a.json()}catch(e){return console.warn(`[API Client] getEvents failed:`,e.message),{total:0,events:[]}}},async getActivityStats(e=null,t=null){try{let n=new URLSearchParams;e&&n.set(`device_id`,e),t&&n.set(`user_id`,t);let r=n.toString(),i=`${API_BASE}/telemetry/stats${r?`?${r}`:``}`,a=await fetch(i,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(4e3)});if(!a.ok)throw Error(`HTTP ${a.status}`);return await a.json()}catch{return{total_stored:0,online_activities:0,offline_activities:0,pending_sync:0,synchronized:0}}},async getDateSummary(e=null,t=null,n=null){try{let r=new URLSearchParams;e&&r.set(`device_id`,e),n&&r.set(`user_id`,n),t!=null&&r.set(`client_tz_offset`,t);let i=await fetch(`${API_BASE}/telemetry/date-summary?${r.toString()}`,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(6e3)});if(!i.ok)throw Error(`HTTP ${i.status}`);return await i.json()}catch(e){return console.warn(`[API Client] getDateSummary failed:`,e.message),{dates:[],total_days:0}}},async recordOfflineActivity(e=`Microsoft Word`,t=`Document Editing`,n=null,r=null){try{let i=new URLSearchParams({app_name:e,action:t});n&&i.set(`device_id`,n),r&&i.set(`user_id`,r);let a=await fetch(`${API_BASE}/telemetry/record-offline?${i.toString()}`,{method:`POST`,headers:this.getAuthHeaders(),signal:AbortSignal.timeout(4e3)});if(!a.ok)throw Error(`HTTP ${a.status}`);return await a.json()}catch(e){return console.warn(`[API Client] recordOfflineActivity failed:`,e),null}},async getEventIncident(e){try{let t=await fetch(`${API_BASE}/telemetry/events/${encodeURIComponent(e)}/incident`,{signal:AbortSignal.timeout(4e3)});if(!t.ok)return null;let n=await t.json();return n.found?n.incident:null}catch{return null}},async getMonitoringStatus(){try{let e=await fetch(`${API_BASE}/monitoring/status`,{signal:AbortSignal.timeout(3e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch{return{active:!1,device_id:`UNKNOWN`,os_info:`Unknown`}}},async getMonitoringHealth(){try{let e=await fetch(`${API_BASE}/monitoring/health`,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(3e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch{return null}},async toggleMonitoring(e){try{return await(await fetch(`${API_BASE}/monitoring/toggle`,{method:`POST`,headers:{"Content-Type":`application/json`},body:JSON.stringify({enabled:e}),signal:AbortSignal.timeout(3e3)})).json()}catch{return{active:!1}}},async recordBrowserEvent(e,t,n=null){try{return await(await fetch(`${API_BASE}/browser/event`,{method:`POST`,headers:{"Content-Type":`application/json`},body:JSON.stringify({url:e,user_id:t,device_id:n}),signal:AbortSignal.timeout(4e3)})).json()}catch{return null}},async getDashboardOverview(){try{let e=await fetch(`${API_BASE}/dashboard/overview`,{signal:AbortSignal.timeout(4e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch{return null}},async ingestEvent(e){try{let t=await fetch(`${API_BASE}/telemetry/event`,{method:`POST`,headers:{"Content-Type":`application/json`},body:JSON.stringify(e),signal:AbortSignal.timeout(4e3)});if(!t.ok)throw Error(`HTTP ${t.status}`);return await t.json()}catch(e){return console.warn(`[API Client] Event ingestion failed:`,e.message),null}},async getKnowledgeGraph(e=100){try{let t=await fetch(`${API_BASE}/graph?max_nodes=${e}`,{signal:AbortSignal.timeout(4e3)});if(!t.ok)throw Error(`HTTP ${t.status}`);return await t.json()}catch(e){return console.warn(`[API Client] Could not fetch backend graph:`,e.message),null}},async getIncidents(e=null){try{let t=`${API_BASE}/incidents`;e&&(t+=`?device_id=${encodeURIComponent(e)}`);let n=await fetch(t,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(4e3)});if(!n.ok)throw Error(`HTTP ${n.status}`);return await n.json()}catch(e){return console.warn(`[API Client] Could not fetch incidents:`,e.message),null}},async getIncident(e){try{let t=await fetch(`${API_BASE}/incidents/${encodeURIComponent(e)}`,{signal:AbortSignal.timeout(4e3)});if(!t.ok)throw Error(`HTTP ${t.status}`);return await t.json()}catch(e){return console.warn(`[API Client] Could not fetch incident:`,e.message),null}},async getWhatChanged(e=`researcher_alice`){try{let t=await fetch(`${API_BASE}/what-changed/${encodeURIComponent(e)}`,{signal:AbortSignal.timeout(4e3)});if(!t.ok)throw Error(`HTTP ${t.status}`);return await t.json()}catch(e){return console.warn(`[API Client] Could not fetch What Changed report:`,e.message),null}},async getResponseRecommendation(e,t={}){try{let n=await fetch(`${API_BASE}/response/recommend`,{method:`POST`,headers:{"Content-Type":`application/json`},body:JSON.stringify({risk_score:e,...t}),signal:AbortSignal.timeout(4e3)});if(!n.ok)throw Error(`HTTP ${n.status}`);return await n.json()}catch(e){return console.warn(`[API Client] Could not fetch recommendation:`,e.message),null}},async queryInvestigator(e,t=null,n=null){try{let r=await fetch(`${API_BASE}/investigator/chat`,{method:`POST`,headers:{"Content-Type":`application/json`},body:JSON.stringify({query:e,incident_id:t,user_id:n}),signal:AbortSignal.timeout(6e3)});if(!r.ok)throw Error(`HTTP ${r.status}`);return await r.json()}catch(e){return console.warn(`[API Client] Investigator query failed:`,e.message),null}},async launchScenario(e){try{let t=await fetch(`${API_BASE}/demo/scenario/${e}`,{method:`POST`,headers:{"Content-Type":`application/json`},signal:AbortSignal.timeout(6e3)});if(!t.ok)throw Error(`HTTP ${t.status}`);return await t.json()}catch(e){return console.warn(`[API Client] Scenario launch failed:`,e.message),null}},async toggleSyncMode(e){try{let t=await fetch(`${API_BASE}/sync/toggle-mode`,{method:`POST`,headers:{"Content-Type":`application/json`},body:JSON.stringify({online:e}),signal:AbortSignal.timeout(4e3)});if(!t.ok)throw Error(`HTTP ${t.status}`);return await t.json()}catch(e){return console.warn(`[API Client] Toggle sync mode failed:`,e.message),null}},async runProtectionTest(){try{let e=await fetch(`${API_BASE}/protection/test`,{method:`POST`,headers:{"Content-Type":`application/json`},signal:AbortSignal.timeout(8e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch(e){throw console.warn(`[API Client] Protection test failed:`,e.message),e}},async testUrl(e,t=`current_user`){try{let n=await fetch(`${API_BASE}/test/browser-event`,{method:`POST`,headers:{"Content-Type":`application/json`},body:JSON.stringify({url:e,user_id:t}),signal:AbortSignal.timeout(1e4)});if(!n.ok){let e=await n.json().catch(()=>({}));throw Error(e.detail||`HTTP ${n.status}`)}return await n.json()}catch(e){throw console.warn(`[API Client] URL test failed:`,e.message),e}},async deleteDevice(e){try{let t=await fetch(`${API_BASE}/devices/${encodeURIComponent(e)}`,{method:`DELETE`,signal:AbortSignal.timeout(5e3)});if(!t.ok){let e=await t.json().catch(()=>({}));throw Error(e.detail||`HTTP ${t.status}`)}return await t.json()}catch(e){throw console.warn(`[API Client] Delete device failed:`,e.message),e}},async getSyncQueue(){try{let e=await fetch(`${API_BASE}/sync/queue`,{signal:AbortSignal.timeout(3e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch{return{pending_count:0,online:!1}}},async triggerSync(){try{let e=await fetch(`${API_BASE}/sync/trigger`,{method:`POST`,signal:AbortSignal.timeout(8e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch(e){throw console.warn(`[API Client] Sync trigger failed:`,e.message),e}},async getShieldStatus(){try{let e=await fetch(`${API_BASE}/shield/status`,{signal:AbortSignal.timeout(4e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch(e){return console.warn(`[API Client] getShieldStatus failed:`,e.message),null}},async runShieldBenchmark(){try{let e=await fetch(`${API_BASE}/shield/benchmark/run`,{method:`POST`,signal:AbortSignal.timeout(2e4)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch(e){throw console.warn(`[API Client] runShieldBenchmark failed:`,e.message),e}},async getShieldThreats(){try{let e=await fetch(`${API_BASE}/shield/threats`,{signal:AbortSignal.timeout(3e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch{return{primary_queue:[],secondary_queue:[]}}},async getReconstructionBenchmark(){try{let e=await fetch(`${API_BASE}/benchmarks/reconstruction`,{signal:AbortSignal.timeout(6e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch(e){return console.warn(`[API Client] getReconstructionBenchmark failed:`,e.message),null}},async getMonitoringProof(){try{let e=await fetch(`${API_BASE}/benchmarks/monitoring-proof`,{signal:AbortSignal.timeout(6e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch(e){return console.warn(`[API Client] getMonitoringProof failed:`,e.message),null}},async getRiskPrediction(e=null){try{let t=`${API_BASE}/risk/predict`;e&&(t+=`?device_id=${encodeURIComponent(e)}`);let n=await fetch(t,{signal:AbortSignal.timeout(5e3)});if(!n.ok)throw Error(`HTTP ${n.status}`);return await n.json()}catch(e){return console.warn(`[API Client] getRiskPrediction failed:`,e.message),null}},async getPredictionBenchmark(){try{let e=await fetch(`${API_BASE}/benchmarks/prediction`,{signal:AbortSignal.timeout(6e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch(e){return console.warn(`[API Client] getPredictionBenchmark failed:`,e.message),null}},async getDeepLearningBenchmark(){try{let e=await fetch(`${API_BASE}/benchmarks/deep-learning`,{signal:AbortSignal.timeout(6e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch(e){return console.warn(`[API Client] getDeepLearningBenchmark failed:`,e.message),null}},async getRlAgentBenchmark(){try{let e=await fetch(`${API_BASE}/benchmarks/rl-agent`,{signal:AbortSignal.timeout(6e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch(e){return console.warn(`[API Client] getRlAgentBenchmark failed:`,e.message),null}},async getQResponseRecommendation(e,t=0,n=1,r=`endpoint`){try{let i=await fetch(`${API_BASE}/response/q-recommend`,{method:`POST`,headers:{"Content-Type":`application/json`},body:JSON.stringify({risk_score:e,velocity:t,blast_radius:n,asset_type:r}),signal:AbortSignal.timeout(5e3)});if(!i.ok)throw Error(`HTTP ${i.status}`);return await i.json()}catch(e){return console.warn(`[API Client] getQResponseRecommendation failed:`,e.message),null}},async getAccurateDeviceDetails(e=null,u=null){try{if(e&&e.startsWith("usr_")){u=e;e=null;}let params=new URLSearchParams();if(e)params.set("device_id",e);if(u)params.set("user_id",u);let t=`${API_BASE}/device/accurate-details${params.toString()?"?"+params.toString():""}`,n=await fetch(t,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(5e3)});if(!n.ok)throw Error(`HTTP ${n.status}`);return await n.json()}catch(err){return console.warn("[API Client] getAccurateDeviceDetails failed:",err.message),null}},async getAccurateUserDetails(e=null){try{let t=e?`${API_BASE}/user/details?user_id=${encodeURIComponent(e)}`:`${API_BASE}/user/details`,n=await fetch(t,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(5e3)});if(!n.ok)throw Error(`HTTP ${n.status}`);return await n.json()}catch(e){return console.warn(`[API Client] getAccurateUserDetails failed:`,e.message),null}},async getSystemAccuracy(){try{let e=await fetch(`${API_BASE}/system/accuracy`,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(5e3)});if(!e.ok)throw Error(`HTTP ${e.status}`);return await e.json()}catch(e){return console.warn(`[API Client] getSystemAccuracy failed:`,e.message),null}},async autoRegisterChromeExtension(e,t=null){try{let n=await fetch(`${API_BASE}/chrome-extension/auto-register`,{method:`POST`,headers:this.getAuthHeaders(),body:JSON.stringify({email:e,device_id:t}),signal:AbortSignal.timeout(6e3)});if(!n.ok)throw Error(`HTTP ${n.status}`);return await n.json()}catch(e){return console.warn(`[API Client] autoRegisterChromeExtension failed:`,e.message),null}},async getExtensionStatus(e=null){try{let t=e?`${API_BASE}/extension/status?device_id=${encodeURIComponent(e)}`:`${API_BASE}/extension/status`,n=await fetch(t,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(4e3)});if(!n.ok)throw Error(`HTTP ${n.status}`);return await n.json()}catch(e){return{installed:!1,connected:!1,paired:!1,error:e.message}}},async pairExtension(e,t=null,n=null){try{let r=await fetch(`${API_BASE}/extension/pair`,{method:`POST`,headers:{"Content-Type":`application/json`,...this.getAuthHeaders()},body:JSON.stringify({email:e,device_id:t,user_id:n}),signal:AbortSignal.timeout(6e3)});if(!r.ok){let e=await r.json().catch(()=>({}));throw Error(e.detail||`HTTP ${r.status}`)}return await r.json()}catch(e){throw console.warn(`[API Client] pairExtension failed:`,e.message),e}},async launchProtectedBrowser(e=`https://google.com`){try{return await(await fetch(`${API_BASE}/browser/launch`,{method:`POST`,headers:{"Content-Type":`application/json`,...this.getAuthHeaders()},body:JSON.stringify({url:e}),signal:AbortSignal.timeout(6e3)})).json()}catch(e){return console.warn(`[API Client] launchProtectedBrowser failed:`,e.message),{status:`error`,message:e.message}}},async getIncidents(e=null,t=null){try{let n=`${API_BASE}/incidents`,r=[];e&&r.push(`device_id=${encodeURIComponent(e)}`),t&&r.push(`user_id=${encodeURIComponent(t)}`),r.length&&(n+=`?${r.join(`&`)}`);let i=await fetch(n,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(5e3)});return i.ok?await i.json():{total:0,incidents:[]}}catch(e){return console.warn(`[API Client] getIncidents failed:`,e),{total:0,incidents:[]}}},async getIncident(e){try{let t=await fetch(`${API_BASE}/incidents/${encodeURIComponent(e)}`,{headers:this.getAuthHeaders(),signal:AbortSignal.timeout(5e3)});return t.ok?await t.json():null}catch(e){return console.warn(`[API Client] getIncident failed:`,e),null}},async resolveIncident(e){try{return await(await fetch(`${API_BASE}/incidents/${encodeURIComponent(e)}/resolve`,{method:`POST`,headers:this.getAuthHeaders()})).json()}catch(e){return console.warn(`[API Client] resolveIncident failed:`,e),{status:`error`}}},async deleteIncident(e){try{return await(await fetch(`${API_BASE}/incidents/${encodeURIComponent(e)}`,{method:`DELETE`,headers:this.getAuthHeaders()})).json()}catch(e){return console.warn(`[API Client] deleteIncident failed:`,e),{status:`error`}}},

  /**
   * Get Monitored & Allowed Emails for Online Activities
   */
  async getAllowedEmails(userId = null) {
    try {
      const url = userId ? `${API_BASE}/user/allowed-emails?user_id=${encodeURIComponent(userId)}` : `${API_BASE}/user/allowed-emails`;
      const res = await fetch(url, {
        headers: this.getAuthHeaders(),
        signal: AbortSignal.timeout(5000)
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.warn('[API Client] getAllowedEmails failed:', err.message);
      return null;
    }
  },

  /**
   * Add an additional authorized Gmail / email for online activity monitoring
   */
  async addAllowedEmail(email, userId = null) {
    try {
      const res = await fetch(`${API_BASE}/user/allowed-emails`, {
        method: 'POST',
        headers: this.getAuthHeaders(),
        body: JSON.stringify({ email, user_id: userId }),
        signal: AbortSignal.timeout(5000)
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.error('[API Client] addAllowedEmail failed:', err.message);
      throw err;
    }
  },

  /**
   * Remove a user-added email from online activity monitoring
   */
  async removeAllowedEmail(email, userId = null) {
    try {
      const res = await fetch(`${API_BASE}/user/allowed-emails`, {
        method: 'DELETE',
        headers: this.getAuthHeaders(),
        body: JSON.stringify({ email, user_id: userId }),
        signal: AbortSignal.timeout(5000)
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      console.error('[API Client] removeAllowedEmail failed:', err.message);
      throw err;
    }
  }
};
