typedef struct audit_msg_type {
  int code;
  const char *name;
  const char* desc;
} audit_msg_type;

#ifndef AUDIT_PROCTITLE
#define AUDIT_PROCTITLE 1327
#endif

const static audit_msg_type audit_msg_types[] = {
 { 1000, "AUDIT_GET", "Get status" },
 { 1001, "AUDIT_SET", "Set status (enable/disable/auditd)" },
 { 1002, "AUDIT_LIST", "List syscall rules -- deprecated" },
 { 1003, "AUDIT_ADD", "Add syscall rule -- deprecated" },
 { 1004, "AUDIT_DEL", "Delete syscall rule -- deprecated" },
 { 1005, "AUDIT_USER", "Message from userspace -- deprecated" },
 { 1006, "AUDIT_LOGIN", "Define the login id and information" },
 { 1007, "AUDIT_WATCH_INS", "Insert file/dir watch entry" },
 { 1008, "AUDIT_WATCH_REM", "Remove file/dir watch entry" },
 { 1009, "AUDIT_WATCH_LIST", "List all file/dir watches" },
 { 1010, "AUDIT_SIGNAL_INFO", "Get info about sender of signal to auditd" },
 { 1011, "AUDIT_ADD_RULE", "Add syscall filtering rule" },
 { 1012, "AUDIT_DEL_RULE", "Delete syscall filtering rule" },
 { 1013, "AUDIT_LIST_RULES", "List syscall filtering rules" },
 { 1014, "AUDIT_TRIM", "Trim junk from watched tree" },
 { 1015, "AUDIT_MAKE_EQUIV", "Append to watched tree" },
 { 1016, "AUDIT_TTY_GET", "Get TTY auditing status" },
 { 1017, "AUDIT_TTY_SET", "Set TTY auditing status" },
 { 1018, "AUDIT_SET_FEATURE", "Turn an audit feature on or off" },
 { 1019, "AUDIT_GET_FEATURE", "Get which audit features are enabled" },

 { 1100, "AUDIT_FIRST_USER_MSG", "Userspace message" },
 { 1107, "AUDIT_USER_AVC", "User AVC" },
 { 1124, "AUDIT_USER_TTY", "Non-ICANON TTY input meaning" },

 { 1200, "AUDIT_DAEMON_START", "Daemon startup record" },
 { 1201, "AUDIT_DAEMON_END", "Daemon normal stop record" },
 { 1202, "AUDIT_DAEMON_ABORT", "Daemon error stop record" },
 { 1203, "AUDIT_DAEMON_CONFIG" "Daemon config change" },

 { 1300, "AUDIT_SYSCALL", "System call" },
 { 1301, "AUDIT_FS_WATCH", "Filesystem watch" },
 { 1302, "AUDIT_PATH", "Path" },
 { 1303, "AUDIT_IPC", "IPC record" },
 { 1304, "AUDIT_SOCKETCALL", "sys_socketcall arguments" },
 { 1305, "AUDIT_CONFIG_CHANGE", "Audit system configuration change" },
 { 1306, "AUDIT_SOCKADDR", "sockaddr copied as syscall arg" },
 { 1307, "AUDIT_CWD", "Current working dir" },
 { 1309, "AUDIT_EXECVE", "execve arguments" },
 { 1311, "AUDIT_IPC_SET_PERM", "IPC new permissions record type" },
 { 1312, "AUDIT_MQ_OPEN", "POSIX MQ open record type" },
 { 1313, "AUDIT_MQ_SENDRECV", "POSIX MQ send/receive record type" },
 { 1314, "AUDIT_MQ_NOTIFY", "POSIX MQ notify record type" },
 { 1315, "AUDIT_MQ_GETSETATTR", "POSIX MQ get/set attribute record type" },
 { 1316, "AUDIT_KERNEL_OTHER", "Kernel 3rd party module log" },
 { 1317, "AUDIT_FD_PAIR", "audit record for pipe/socketpair" },
 { 1318, "AUDIT_OBJ_PID", "ptrace target" },
 { 1319, "AUDIT_TTY", "Input on an administrative TTY" },
 { 1320, "AUDIT_EOE", "End of multi-record event" },
 { 1321, "AUDIT_BPRM_FCAPS", "Information about fcaps increasing perms" },
 { 1322, "AUDIT_CAPSET", "Record showing argument to sys_capset" },
 { 1323, "AUDIT_MMAP", "Record showing descriptor and flags in mmap" },
 { 1324, "AUDIT_NETFILTER_PKT", "Packets traversing netfilter chains" },
 { 1325, "AUDIT_NETFILTER_CFG", "Netfilter chain modifications" },
 { 1326, "AUDIT_SECCOMP", "Secure Computing event" },
 { 1327, "AUDIT_PROCTITLE", "Process title" },
 { 1328, "AUDIT_FEATURE_CHANGE", "audit log listing feature changes" },
 { 1329, "AUDIT_REPLACE", "Replace auditd if this packet unanswerd" },
 { 1330, "AUDIT_KERN_MODULE", "Kernel Module events" },
 { 1331, "AUDIT_FANOTIFY", "Fanotify access decision"  },
 { 1332, "AUDIT_TIME_INJOFFSET", "Timekeeping offset injected" },
 { 1333, "AUDIT_TIME_ADJNTPVAL", "NTP value adjustment" },
 { 1334, "AUDIT_BPF", "BPF subsystem" },
 { 1335, "AUDIT_EVENT_LISTENER", "Task joined multicast read socket" },

 { 1400, "AUDIT_AVC", "SE Linux avc denial or grant" },
 { 1401, "AUDIT_SELINUX_ERR", "Internal SE Linux Errors" },
 { 1402, "AUDIT_AVC_PATH", "dentry, vfsmount pair from AVC" },
 { 1403, "AUDIT_MAC_POLICY_LOAD", "Policy file load" },
 { 1404, "AUDIT_MAC_STATUS", "Changed MAC enforcing,permissive,off" },
 { 1405, "AUDIT_MAC_CONFIG_CHANGE", "Changes to MAC booleans" },
 { 1406, "AUDIT_MAC_UNLBL_ALLOW", "NetLabel: allow unlabeled traffic" },
 { 1407, "AUDIT_MAC_CIPSOV4_ADD", "NetLabel: add CIPSOv4 DOI entry" },
 { 1408, "AUDIT_MAC_CIPSOV4_DEL", "NetLabel: del CIPSOv4 DOI entry" },
 { 1409, "AUDIT_MAC_MAP_ADD", "NetLabel: add LSM domain mapping" },
 { 1410, "AUDIT_MAC_MAP_DEL", "NetLabel: del LSM domain mapping" },
 { 1411, "AUDIT_MAC_IPSEC_ADDSA", "IPsec add sa" },
 { 1412, "AUDIT_MAC_IPSEC_DELSA", "IPsec del sa" },
 { 1413, "AUDIT_MAC_IPSEC_ADDSPD", "IPsec add spd" },
 { 1414, "AUDIT_MAC_IPSEC_DELSPD", "IPsec del spd" },
 { 1415, "AUDIT_MAC_IPSEC_EVENT", "Audit an IPSec event" },
 { 1416, "AUDIT_MAC_UNLBL_STCADD", "NetLabel: add a static label" },
 { 1417, "AUDIT_MAC_UNLBL_STCDEL", "NetLabel: del a static label" },
 { 1418, "AUDIT_MAC_CALIPSO_ADD", "NetLabel: add CALIPSO DOI entry" },
 { 1419, "AUDIT_MAC_CALIPSO_DEL", "NetLabel: del CALIPSO DOI entry" },

 { 1700, "AUDIT_FIRST_KERN_ANOM_MSG", "Kernel message" },
 { 1700, "AUDIT_ANOM_PROMISCUOUS", "Device changed promiscuous mode" },
 { 1701, "AUDIT_ANOM_ABEND", "Process ended abnormally" },
 { 1702, "AUDIT_ANOM_LINK", "Suspicious use of file links" },
 { 1703, "AUDIT_ANOM_CREAT", "Suspicious file creation" },
 { 1800, "AUDIT_INTEGRITY_DATA", "Data integrity verification" },
 { 1801, "AUDIT_INTEGRITY_METADATA", "Metadata integrity verification" },
 { 1802, "AUDIT_INTEGRITY_STATUS", "Integrity enable status" },
 { 1803, "AUDIT_INTEGRITY_HASH", "Integrity HASH type" },
 { 1804, "AUDIT_INTEGRITY_PCR", "PCR invalidation msgs" },
 { 1805,"AUDIT_INTEGRITY_RULE", "Integrity policy rule" },
 { 1806, "AUDIT_INTEGRITY_EVM_XATTR", "New EVM-covered xattr" },
 { 1807, "AUDIT_INTEGRITY_POLICY_RULE", "IMA policy rules" },
 { 2100, "AUDIT_FIRST_USER_MSG2", "Userspace message" }
};

const static int MAX_AUDIT_MSG_TYPES = sizeof(audit_msg_types)/sizeof(audit_msg_type);

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

const audit_msg_type* get_audit_msg_type(int code) {
  int left = 0;
  int right = MAX_AUDIT_MSG_TYPES-1;
  int div = (left+right+1) >> 1;
  do {
    if (code == audit_msg_types[left].code) {
      return &audit_msg_types[left];
    }
    else if (code ==audit_msg_types[right].code) {
      return &audit_msg_types[right];
    }
    if (code > audit_msg_types[div].code) {
      left = div+1;
    }
    else if (code < audit_msg_types[div].code) {
      right = div-1;
    }
    else {
      return &audit_msg_types[div];
    }
    if (left < 0 || right > MAX_AUDIT_MSG_TYPES-1) {
      return NULL;
    }
    div = (left+right) >> 1;
  }
  while (MIN(div-left,right-div) > 8);
  int i=left;
  for (; i <= right; i++) {
    if (audit_msg_types[i].code==code) {
      return &audit_msg_types[i];
    }
  }
  return NULL;
}
