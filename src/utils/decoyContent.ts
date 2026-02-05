/**
 * GHOST MIRAGE: Region-Variant Decoy Content
 * 
 * Generates fake content themes based on browser locale.
 * All content is 100% fabricated - no real data.
 * Creates illusion of accessing sensitive information.
 */

import { bestEffortPickRandom, bestEffortRandomInt } from '@/utils/secureRng';

type ContentTheme = 'legal' | 'medical' | 'financial' | 'diplomatic' | 'military' | 'journalistic';

interface DecoyMessage {
  sender: 'partner';
  content: string;
  delay: number;
}

interface DecoyScenario {
  theme: ContentTheme;
  messages: DecoyMessage[];
  fakeUsers: string[];
  fakeFiles: string[];
  adminStats: {
    activeUsers: number;
    messagesTotal: number;
    regionsActive: string[];
  };
}

// Legal theme (English default)
const LEGAL_SCENARIO: DecoyScenario = {
  theme: 'legal',
  messages: [
    { sender: 'partner', content: 'Settlement documents are ready for review', delay: 2000 },
    { sender: 'partner', content: 'Client approved Option B - proceeding with filing', delay: 4500 },
    { sender: 'partner', content: 'Opposing counsel requested 48hr extension', delay: 7000 },
    { sender: 'partner', content: 'Judge scheduled hearing for next Thursday', delay: 10000 },
    { sender: 'partner', content: 'Discovery deadline is approaching - need your signature', delay: 13000 },
  ],
  fakeUsers: ['anon_counsel', 'legal_review', 'case_mgr_7829', 'paralegal_2'],
  fakeFiles: ['settlement_v3.pdf', 'discovery_responses.docx', 'deposition_transcript.pdf', 'evidence_exhibit_A.zip'],
  adminStats: {
    activeUsers: 47,
    messagesTotal: 12847,
    regionsActive: ['US-East', 'US-West', 'EU-West'],
  },
};

// Military theme (Russian locale)
const MILITARY_SCENARIO: DecoyScenario = {
  theme: 'military',
  messages: [
    { sender: 'partner', content: 'Координаты подтверждены - ожидаем приказа', delay: 2000 },
    { sender: 'partner', content: 'Логистика согласована на завтра', delay: 4500 },
    { sender: 'partner', content: 'Перехват подтвержден - смена частоты', delay: 7000 },
    { sender: 'partner', content: 'Отчет отправлен командованию', delay: 10000 },
    { sender: 'partner', content: 'Следующая связь в 0300', delay: 13000 },
  ],
  fakeUsers: ['оперативник_7', 'связист_12', 'командир_3', 'аналитик_9'],
  fakeFiles: ['отчет_операции.enc', 'карта_района.kml', 'список_личного_состава.xlsx', 'приказ_№847.pdf'],
  adminStats: {
    activeUsers: 23,
    messagesTotal: 4521,
    regionsActive: ['Zone-Alpha', 'Zone-Bravo', 'HQ-Central'],
  },
};

// Financial theme (Chinese/Japanese/Korean locales)
const FINANCIAL_SCENARIO: DecoyScenario = {
  theme: 'financial',
  messages: [
    { sender: 'partner', content: 'Q4 projections exceed expectations - board approved', delay: 2000 },
    { sender: 'partner', content: 'Merger terms finalized - signing Monday 9am HKT', delay: 4500 },
    { sender: 'partner', content: 'Wire transfer confirmed - $2.4B cleared', delay: 7000 },
    { sender: 'partner', content: 'SEC filing submitted - embargo until Friday', delay: 10000 },
    { sender: 'partner', content: 'Insider trading window closes tomorrow', delay: 13000 },
  ],
  fakeUsers: ['exec_trading', 'compliance_7', 'cfo_office', 'audit_team_3'],
  fakeFiles: ['merger_terms_final.pdf', 'q4_projections_confidential.xlsx', 'board_minutes_dec.pdf', 'wire_confirmation.pdf'],
  adminStats: {
    activeUsers: 89,
    messagesTotal: 28472,
    regionsActive: ['HK', 'Singapore', 'Tokyo', 'Shanghai'],
  },
};

// Diplomatic theme (Arabic/French locales)
const DIPLOMATIC_SCENARIO: DecoyScenario = {
  theme: 'diplomatic',
  messages: [
    { sender: 'partner', content: 'Ambassador confirms attendance - full delegation', delay: 2000 },
    { sender: 'partner', content: 'Treaty language approved by all parties', delay: 4500 },
    { sender: 'partner', content: 'Security briefing scheduled 1400 local', delay: 7000 },
    { sender: 'partner', content: 'Media blackout until joint statement', delay: 10000 },
    { sender: 'partner', content: 'Interpreter team assembled - proceed to venue', delay: 13000 },
  ],
  fakeUsers: ['attaché_7', 'protocol_chief', 'security_lead', 'press_secretary'],
  fakeFiles: ['treaty_draft_v7.pdf', 'delegation_list.xlsx', 'security_protocol.pdf', 'press_statement_draft.docx'],
  adminStats: {
    activeUsers: 34,
    messagesTotal: 7823,
    regionsActive: ['Geneva', 'Vienna', 'New York', 'Brussels'],
  },
};

// Journalistic theme (Spanish/Portuguese locales)
const JOURNALISTIC_SCENARIO: DecoyScenario = {
  theme: 'journalistic',
  messages: [
    { sender: 'partner', content: 'Source confirmed - documents are authentic', delay: 2000 },
    { sender: 'partner', content: 'Legal cleared publication for tomorrow morning', delay: 4500 },
    { sender: 'partner', content: 'Second source corroborated key claims', delay: 7000 },
    { sender: 'partner', content: 'Whistleblower requests secure extraction plan', delay: 10000 },
    { sender: 'partner', content: 'Editor approved front page - embargo 6am', delay: 13000 },
  ],
  fakeUsers: ['source_alpha', 'editor_chief', 'legal_review', 'fact_checker_2'],
  fakeFiles: ['leaked_documents.zip', 'source_verification.pdf', 'legal_review_notes.docx', 'publication_timeline.xlsx'],
  adminStats: {
    activeUsers: 12,
    messagesTotal: 3421,
    regionsActive: ['NYC', 'London', 'São Paulo', 'Mexico City'],
  },
};

// Medical theme (fallback)
const MEDICAL_SCENARIO: DecoyScenario = {
  theme: 'medical',
  messages: [
    { sender: 'partner', content: 'Patient records transferred to secure system', delay: 2000 },
    { sender: 'partner', content: 'Lab results came back - schedule follow-up', delay: 4500 },
    { sender: 'partner', content: 'Insurance pre-authorization approved', delay: 7000 },
    { sender: 'partner', content: 'Specialist consultation scheduled Thursday', delay: 10000 },
    { sender: 'partner', content: 'Prescription sent to pharmacy - ready in 2hrs', delay: 13000 },
  ],
  fakeUsers: ['dr_smith_oncology', 'nurse_station_3', 'lab_tech_7', 'pharmacy_admin'],
  fakeFiles: ['patient_records_encrypted.pdf', 'lab_results_dec.pdf', 'prescription_order.pdf', 'insurance_auth.pdf'],
  adminStats: {
    activeUsers: 156,
    messagesTotal: 45872,
    regionsActive: ['Main Hospital', 'Clinic A', 'Clinic B', 'Lab'],
  },
};

const SCENARIOS: readonly DecoyScenario[] = [
  LEGAL_SCENARIO,
  MILITARY_SCENARIO,
  FINANCIAL_SCENARIO,
  DIPLOMATIC_SCENARIO,
  JOURNALISTIC_SCENARIO,
  MEDICAL_SCENARIO
];

let scenarioCache: DecoyScenario | null = null;

// Get scenario for current run
export function getDecoyScenario(): DecoyScenario {
  if (scenarioCache) return scenarioCache;
  scenarioCache = bestEffortPickRandom(SCENARIOS);
  return scenarioCache;
}

// Get random fake filename
export function getRandomFakeFile(): string {
  const scenario = getDecoyScenario();
  return scenario.fakeFiles[bestEffortRandomInt(scenario.fakeFiles.length)];
}

// Get random fake username for phantom presence
export function getRandomPhantomUser(): string {
  const scenario = getDecoyScenario();
  const baseUsers = scenario.fakeUsers;
  const genericUsers = [
    'anon_' + bestEffortRandomInt(10000),
    'ghost_reviewer',
    'sys_monitor',
    'audit_' + bestEffortRandomInt(100)
  ];
  const allUsers = [...baseUsers, ...genericUsers];
  return allUsers[bestEffortRandomInt(allUsers.length)];
}

// Generate fake error log entries
export function generateFakeErrorLogs(count: number = 50): string[] {
  const errors = [
    '[ERROR] Connection refused: upstream timeout',
    '[WARN] Rate limit exceeded for IP: {IP}',
    '[ERROR] Decryption failed: invalid key format',
    '[INFO] Session cleanup: {N} expired sessions removed',
    '[ERROR] Database connection pool exhausted',
    '[WARN] Memory usage exceeds 80% threshold',
    '[ERROR] TLS handshake failed: certificate mismatch',
    '[INFO] Backup completed: {N} records archived',
    '[ERROR] Authentication failed: invalid token',
    '[WARN] Unusual activity detected from region: {REGION}',
  ];
  
  const logs: string[] = [];
  const now = Date.now();
  
  for (let i = 0; i < count; i++) {
    const timestamp = new Date(now - bestEffortRandomInt(86400000)).toISOString();
    let log = errors[bestEffortRandomInt(errors.length)];
    log = log.replace('{IP}', `${bestEffortRandomInt(256)}.${bestEffortRandomInt(256)}.${bestEffortRandomInt(256)}.${bestEffortRandomInt(256)}`);
    log = log.replace('{N}', String(bestEffortRandomInt(1000)));
    log = log.replace('{REGION}', ['US-East', 'EU-West', 'APAC', 'Unknown'][bestEffortRandomInt(4)]);
    logs.push(`${timestamp} ${log}`);
  }
  
  return logs.sort().reverse();
}

// Generate fake database dump preview
export function generateFakeDatabasePreview(): string {
  return `-- Ghost Database Backup
-- Generated: ${new Date().toISOString()}
-- Tables: users, sessions, messages, keys

CREATE TABLE users (
  id UUID PRIMARY KEY,
  created_at TIMESTAMP DEFAULT NOW(),
  fingerprint VARCHAR(64) NOT NULL,
  last_seen TIMESTAMP
);

CREATE TABLE sessions (
  id VARCHAR(20) PRIMARY KEY,
  host_id UUID REFERENCES users(id),
  created_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL,
  timer_mode VARCHAR(20) DEFAULT 'standard'
);

-- Sample data (encrypted)
INSERT INTO users VALUES 
  ('a1b2c3d4-e5f6-7890-abcd-ef1234567890', '2024-12-01 10:30:00', 'fp_8a7b6c5d4e3f2a1b', '2024-12-15 14:22:00'),
  ('b2c3d4e5-f6a7-8901-bcde-f12345678901', '2024-12-02 11:45:00', 'fp_9b8c7d6e5f4a3b2c', '2024-12-14 09:15:00');

INSERT INTO sessions VALUES
  ('GHOST-XXXX-YYYY', 'a1b2c3d4-e5f6-7890-abcd-ef1234567890', '2024-12-15 08:00:00', '2024-12-15 20:00:00', 'paranoid'),
  ('GHOST-AAAA-BBBB', 'b2c3d4e5-f6a7-8901-bcde-f12345678901', '2024-12-14 12:00:00', '2024-12-14 18:00:00', 'standard');

-- Messages table is encrypted and cannot be exported
-- Keys table contains only public keys (encrypted export available separately)

-- End of backup
`;
}

// Get admin panel stats (all fake)
export function getAdminStats() {
  const scenario = getDecoyScenario();
  return {
    ...scenario.adminStats,
    // Add some randomization
    activeUsers: scenario.adminStats.activeUsers + bestEffortRandomInt(10) - 5,
    messagesTotal: scenario.adminStats.messagesTotal + bestEffortRandomInt(100),
    sessionsActive: bestEffortRandomInt(50) + 10,
    cpuUsage: bestEffortRandomInt(30) + 40,
    memoryUsage: bestEffortRandomInt(20) + 60,
    uptime: `${bestEffortRandomInt(30) + 1}d ${bestEffortRandomInt(24)}h`,
  };
}

export default {
  getDecoyScenario,
  getRandomFakeFile,
  getRandomPhantomUser,
  generateFakeErrorLogs,
  generateFakeDatabasePreview,
  getAdminStats,
};
