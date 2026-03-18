import cron from 'node-cron';
import { updateAppStats } from '../services/stats.service';

export const startStatsUpdaterJob = () => cron.schedule('0 * * * *', async () => {
  await updateAppStats();
});
