with open('D:/CyberThreat_AI_System/src/components/ActivityView.jsx', 'r', encoding='utf-8') as f:
    code = f.read()

# 1. Update loadActivities to resolve activeUserId reliably
old_uid = "userId: user?.id || undefined,"
new_uid = "userId: user?.id || (typeof localStorage !== 'undefined' ? (JSON.parse(localStorage.getItem('cyberthreat_auth_user') || '{}')?.id) : undefined),"

norm_code = code.replace('\r\n', '\n')
norm_code = norm_code.replace(old_uid, new_uid)

# 2. Optimize filteredEvents with dbEventIdSet
old_filter = '''  // Filter events by Category, Date, and Search
  const filteredEvents = useMemo(() => {
    const todayStr = getTodayStr();
    const yesterdayStr = getYesterdayStr();

    return realEvents.filter(ev => {
      const f = ev.features || {};
      const cat = f.activity_category || '';
      const evType = ev.event_type || '';
      const evDate = getLocalDateStr(ev.timestamp || ev.created_at);

      // 1. Date Filter (Strict local time matching with DB event preservation)
      if (dateFilter === 'TODAY') {
        if (evDate !== todayStr && !dbEvents.some(dbe => dbe.event_id === ev.event_id)) return false;
      } else if (dateFilter === 'YESTERDAY') {
        if (evDate !== yesterdayStr && !dbEvents.some(dbe => dbe.event_id === ev.event_id)) return false;
      } else if (dateFilter === 'CUSTOM') {
        if (evDate !== customDate && !dbEvents.some(dbe => dbe.event_id === ev.event_id)) return false;
      } else if (dateFilter === 'RANGE') {
        if (rangeStartDate && evDate < rangeStartDate) return false;
        if (rangeEndDate && evDate > rangeEndDate) return false;
      }'''

new_filter = '''  // Filter events by Category, Date, and Search
  const filteredEvents = useMemo(() => {
    const todayStr = getTodayStr();
    const yesterdayStr = getYesterdayStr();
    const dbEventIdSet = new Set((dbEvents || []).map(dbe => dbe.event_id));

    return realEvents.filter(ev => {
      const f = ev.features || {};
      const cat = f.activity_category || '';
      const evType = ev.event_type || '';
      const evDate = getLocalDateStr(ev.timestamp || ev.created_at);
      const isFromDbQuery = dbEventIdSet.has(ev.event_id);

      // 1. Date Filter (Strict local time matching with DB event preservation)
      if (dateFilter === 'TODAY') {
        if (evDate !== todayStr && !isFromDbQuery) return false;
      } else if (dateFilter === 'YESTERDAY') {
        if (evDate !== yesterdayStr && !isFromDbQuery) return false;
      } else if (dateFilter === 'CUSTOM') {
        if (evDate !== customDate && !isFromDbQuery) return false;
      } else if (dateFilter === 'RANGE') {
        if (rangeStartDate && evDate < rangeStartDate && !isFromDbQuery) return false;
        if (rangeEndDate && evDate > rangeEndDate && !isFromDbQuery) return false;
      }'''

old_filter_norm = old_filter.replace('\r\n', '\n')
new_filter_norm = new_filter.replace('\r\n', '\n')

assert old_filter_norm in norm_code, 'old_filter not found in ActivityView.jsx'
norm_code = norm_code.replace(old_filter_norm, new_filter_norm)

with open('D:/CyberThreat_AI_System/src/components/ActivityView.jsx', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(norm_code)
print('SUCCESS: ActivityView.jsx updated!')
