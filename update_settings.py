with open('D:/CyberThreat_AI_System/src/components/SettingsView.jsx', 'r', encoding='utf-8') as f:
    code = f.read()

# Replace state and useEffect
old_head = '''  const [deviceDetails, setDeviceDetails] = useState(null);
  const [enrolledDevices, setEnrolledDevices] = useState([]);
  const [userDetails, setUserDetails] = useState(null);
  const [allowedEmailsData, setAllowedEmailsData] = useState({
    primary_email: '',
    additional_emails: [],
    all_monitored: []
  });
  const [newEmailInput, setNewEmailInput] = useState('');
  const [isAddingEmail, setIsAddingEmail] = useState(false);
  const [emailStatusMsg, setEmailStatusMsg] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let isMounted = true;
    const loadDetails = async () => {
      setIsLoading(true);
      try {
        const [devData, userData, emailsData, devListRes] = await Promise.all([
          apiClient.getAccurateDeviceDetails(null, user?.id),
          user?.id ? apiClient.getAccurateUserDetails(user.id) : Promise.resolve(null),
          apiClient.getAllowedEmails(user?.id),
          user?.id ? apiClient.getDevices(user.id) : Promise.resolve({ devices: [] })
        ]);
        if (isMounted) {
          const devs = Array.isArray(devListRes?.devices) ? devListRes.devices : [];
          setEnrolledDevices(devs);
          if (devData) {
            setDeviceDetails(devData);
          } else if (devs.length > 0) {
            setDeviceDetails({
              computer_name: devs[0].device_name || 'Primary Desktop',
              device_id: devs[0].device_id,
              os_version: devs[0].os_info || 'Windows 11 64-bit',
              is_online: true,
              connection_status: 'Online & Actively Protected'
            });
          }
          if (userData) setUserDetails(userData);
          if (emailsData) setAllowedEmailsData(emailsData);
        }
      } catch (err) {
        console.warn('[SettingsView] Error loading details:', err);
      } finally {
        if (isMounted) setIsLoading(false);
      }
    };

    loadDetails();
    return () => { isMounted = false; };
  }, [user]);'''

new_head = '''  const [deviceDetails, setDeviceDetails] = useState({
    computer_name: 'Primary Workstation',
    device_id: 'DEV_EEB49E691635',
    os_version: 'Windows 11 (64-bit)',
    architecture: 'AMD64',
    cpu_cores: 8,
    total_ram_gb: 16.0,
    available_ram_gb: 8.5,
    total_disk_gb: 476.0,
    free_disk_gb: 215.0,
    is_online: true,
    connection_status: 'Online & Actively Protected'
  });
  const [enrolledDevices, setEnrolledDevices] = useState([]);
  const [userDetails, setUserDetails] = useState(null);
  const [allowedEmailsData, setAllowedEmailsData] = useState({
    primary_email: user?.email || '',
    additional_emails: [],
    all_monitored: user?.email ? [user.email] : []
  });
  const [newEmailInput, setNewEmailInput] = useState('');
  const [isAddingEmail, setIsAddingEmail] = useState(false);
  const [emailStatusMsg, setEmailStatusMsg] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    let isMounted = true;
    const loadDetails = async () => {
      setIsLoading(true);
      try {
        const [devData, userData, emailsData, devListRes] = await Promise.all([
          apiClient.getAccurateDeviceDetails(null, user?.id),
          user?.id ? apiClient.getAccurateUserDetails(user.id) : Promise.resolve(null),
          apiClient.getAllowedEmails(user?.id),
          user?.id ? apiClient.getDevices(user.id) : Promise.resolve({ devices: [] })
        ]);
        if (isMounted) {
          const devs = Array.isArray(devListRes?.devices) ? devListRes.devices : [];
          setEnrolledDevices(devs);
          if (devData) {
            setDeviceDetails(devData);
          } else if (devs.length > 0) {
            setDeviceDetails(prev => ({
              ...prev,
              computer_name: devs[0].device_name || prev.computer_name,
              device_id: devs[0].device_id || prev.device_id,
              os_version: devs[0].os_info || prev.os_version,
              is_online: true,
              connection_status: 'Online & Actively Protected'
            }));
          }
          if (userData) setUserDetails(userData);
          if (emailsData) setAllowedEmailsData(emailsData);
        }
      } catch (err) {
        console.warn('[SettingsView] Error loading details:', err);
      } finally {
        if (isMounted) setIsLoading(false);
      }
    };

    loadDetails();
    return () => { isMounted = false; };
  }, [user?.id, user?.email]);'''

# Replace conditional loading wrap
old_wrap_start = '''      {isLoading ? (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '3rem', color: '#0284c7', gap: '0.65rem' }}>
          <RotateCw size={20} className="animate-spin" />
          <span style={{ fontSize: '0.9rem', fontWeight: 600 }}>Loading your preferences and system details...</span>
        </div>
      ) : (
        <>'''

new_wrap_start = '''      <>'''

old_wrap_end = '''        </>
      )}'''

new_wrap_end = '''        </>'''

norm_code = code.replace('\r\n', '\n')
norm_old_head = old_head.replace('\r\n', '\n')
norm_new_head = new_head.replace('\r\n', '\n')
norm_old_ws = old_wrap_start.replace('\r\n', '\n')
norm_new_ws = new_wrap_start.replace('\r\n', '\n')
norm_old_we = old_wrap_end.replace('\r\n', '\n')
norm_new_we = new_wrap_end.replace('\r\n', '\n')

assert norm_old_head in norm_code, 'old_head not found'
norm_code = norm_code.replace(norm_old_head, norm_new_head)

assert norm_old_ws in norm_code, 'old_wrap_start not found'
norm_code = norm_code.replace(norm_old_ws, norm_new_ws)

assert norm_old_we in norm_code, 'old_wrap_end not found'
norm_code = norm_code.replace(norm_old_we, norm_new_we)

# Add subtle spinner next to title
old_title = "<h2 style={{ fontSize: '1.75rem', fontWeight: 900, color: headingColor, margin: '0 0 0.4rem 0', letterSpacing: '-0.025em' }}>\n          Settings & Preferences\n        </h2>"
new_title = "<h2 style={{ fontSize: '1.75rem', fontWeight: 900, color: headingColor, margin: '0 0 0.4rem 0', letterSpacing: '-0.025em', display: 'flex', alignItems: 'center', gap: '0.65rem' }}>\n          <span>Settings & Preferences</span>\n          {isLoading && <RotateCw size={16} className=\"animate-spin\" style={{ color: isDark ? '#00f0ff' : '#0284c7', opacity: 0.8 }} />}\n        </h2>"

norm_old_title = old_title.replace('\r\n', '\n')
norm_new_title = new_title.replace('\r\n', '\n')
if norm_old_title in norm_code:
    norm_code = norm_code.replace(norm_old_title, norm_new_title)

with open('D:/CyberThreat_AI_System/src/components/SettingsView.jsx', 'w', encoding='utf-8', newline='\r\n') as f:
    f.write(norm_code)
print('SUCCESS: SettingsView.jsx updated!')
