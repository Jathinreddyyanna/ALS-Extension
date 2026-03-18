import { SettingsTab } from '@/popup/tabs/SettingsTab';

export const SettingsPanel = () => (
  <div className="space-y-4">
    <div>
      <p className="heading">Protection settings</p>
      <p className="caption">Choose how Browser Shield should support you.</p>
    </div>
    <SettingsTab />
  </div>
);
