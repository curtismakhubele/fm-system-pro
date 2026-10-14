(function () {
  function normalizeText(value) {
    return String(value || '')
      .toLowerCase()
      .normalize('NFD')
      .replace(/[\u0300-\u036f]/g, '')
      .trim();
  }

  function scoreMatch(query, value, exactBonus = 0) {
    const normalizedQuery = normalizeText(query);
    const normalizedValue = normalizeText(value);
    if (!normalizedQuery || !normalizedValue) return 0;

    if (normalizedValue === normalizedQuery) return 100 + exactBonus;
    if (normalizedValue.startsWith(normalizedQuery)) return 70 + exactBonus;
    if (normalizedValue.includes(normalizedQuery)) return 45 + exactBonus;
    return 0;
  }

  function buildGlobalSearchResults(data, query) {
    const q = normalizeText(query);
    if (!q || !data) return [];

    const matches = [];

    function addMatch(type, item, title, subtitle, view, scoreBonus = 0) {
      const score = scoreMatch(q, title, scoreBonus) || scoreMatch(q, subtitle, scoreBonus) || scoreMatch(q, item.id || '', scoreBonus) || 0;
      if (!score) return;
      matches.push({ type, id: item.id || title, title, subtitle: subtitle || 'Match found', view, score, centreId: item.centreId || '' });
    }

    (data.centres || []).forEach((centre) => {
      addMatch('Centre', centre, centre.name || 'Centre', centre.location || centre.id || 'Centre record', 'centres', 12);
    });

    (data.assets || []).forEach((asset) => {
      addMatch('Asset', asset, asset.name || asset.id || 'Asset', `${asset.id || 'Asset'} • ${asset.location || 'Unknown location'} • ${asset.centreId || 'Unassigned'}`, 'assets', 18);
      addMatch('Asset', asset, asset.id || asset.name || 'Asset', `${asset.name || 'Asset'} • ${asset.location || 'Unknown location'}`, 'assets', 20);
    });

    (data.workOrders || []).forEach((workOrder) => {
      addMatch('Work Order', workOrder, workOrder.title || workOrder.id || 'Work order', `${workOrder.id || 'WO'} • ${workOrder.assetId || 'No asset'} • ${workOrder.status || 'open'}`, 'workorders', 25);
      addMatch('Work Order', workOrder, workOrder.id || workOrder.title || 'Work order', `${workOrder.title || 'Untitled'} • ${workOrder.status || 'open'}`, 'workorders', 30);
    });

    (data.pmTasks || []).forEach((task) => {
      addMatch('Maintenance', task, task.task || task.id || 'Maintenance task', `${task.id || 'PM'} • ${task.assetId || 'No asset'} • ${task.nextDue || 'No date'}`, 'maintenance', 10);
    });

    (data.projects || []).forEach((project) => {
      addMatch('Project', project, project.name || project.id || 'Project', `${project.id || 'PR'} • ${project.status || 'active'}`, 'projects', 12);
      addMatch('Project', project, project.id || project.name || 'Project', `${project.name || 'Untitled'} • ${project.status || 'active'}`, 'projects', 15);
    });

    (data.incidents || []).forEach((incident) => {
      addMatch('Incident', incident, incident.type || incident.id || 'Incident', `${incident.id || 'INC'} • ${incident.centreId || 'Unknown centre'}`, 'ohsa', 8);
    });

    return matches
      .sort((a, b) => b.score - a.score || a.type.localeCompare(b.type))
      .slice(0, 8);
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { normalizeText, buildGlobalSearchResults };
  }

  if (typeof window !== 'undefined') {
    window.buildGlobalSearchResults = buildGlobalSearchResults;
  }
})();
